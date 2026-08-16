//! Choosing a tuple nobody else is using. This is where NAT is either correct
//! or silently broken: handing out a tuple that is already live merges two
//! conversations, and giving up too early drops connections under load.

use conntrack::limits::{NAT_HARDER_THRESH, NAT_MAX_ATTEMPTS};
use conntrack::tuple::Tuple;

use crate::range::*;
use crate::uapi::*;

/// What the search may consult and how it draws randomness. Injecting both
/// keeps the whole allocator a pure function, so the collision behaviour is
/// testable without a live table.
pub trait NatEnv {
    /// Whether some other live flow already presents `t` on the wire.
    /// # C: O(bucket length)
    fn tuple_taken(&self, t: &Tuple) -> bool;
    /// Random 16-bit offset for the port search.
    /// # C: O(1)
    fn random_u16(&self) -> u16;
    /// Try to free the port `t` holds by evicting a flow that is already
    /// closing. `false` when nothing could be evicted.
    /// # C: O(bucket length)
    fn try_evict(&self, _t: &Tuple) -> bool { false }
    /// A previously chosen source mapping for this client, if one is still
    /// live. Reusing it is what makes NAT consistent for a given client.
    /// # C: O(bucket length)
    fn find_appropriate_src(&self, _orig: &Tuple, _r: &NatRange) -> Option<Tuple> { None }
}

/// Search for a free port or id inside the range. Returns the mutated tuple,
/// or `None` when the window is exhausted.
///
/// The search is bounded: an unbounded scan of 64k ports runs in softirq
/// context on every new flow, so it takes at most `NAT_MAX_ATTEMPTS` probes,
/// then halves the budget and retries from a fresh offset until the budget
/// falls below a floor. That is a best-effort guarantee, not an absolute one.
/// # C: O(NAT_MAX_ATTEMPTS · bucket length)
pub fn unique_tuple<E: NatEnv>(tuple: &Tuple, r: &NatRange, manip: u8, env: &E)
    -> Option<Tuple>
{
    let Some((min, range_size)) = proto_window(tuple, r, manip) else {
        return Some(*tuple);
    };
    if range_size == 0 { return None; }

    let mut off: u32 = if r.flags & NF_NAT_RANGE_PROTO_OFFSET != 0 {
        manip_port(tuple, manip).wrapping_sub(r.base_proto) as u32
    } else if r.random() || manip != NF_NAT_MANIP_DST {
        env.random_u16() as u32
    } else {
        0
    };

    let mut attempts = core::cmp::min(range_size, NAT_MAX_ATTEMPTS);
    loop {
        for i in 0..attempts {
            let mut cand = *tuple;
            let port = (min as u32).wrapping_add((off.wrapping_add(i)) % range_size);
            set_manip_port(&mut cand, manip, port as u16);
            if !taken_harder(&cand, env, attempts - i) { return Some(cand); }
        }
        // Halving rather than widening: a range that is genuinely full will
        // not yield to more probes, and the cost is paid per packet.
        if attempts >= range_size || attempts < 16 { return None; }
        attempts /= 2;
        off = env.random_u16() as u32;
    }
}

/// Collision test that becomes willing to evict a closing flow once the search
/// is nearly out of attempts.
fn taken_harder<E: NatEnv>(t: &Tuple, env: &E, attempts_left: u32) -> bool {
    if !env.tuple_taken(t) { return false; }
    if attempts_left > NAT_HARDER_THRESH { return true; }
    !env.try_evict(t)
}

/// Full tuple selection for one binding.
///
/// The order matters and each step exists for a reason:
///  1. a source translation that is already inside the range and unused keeps
///     the original tuple, so an unnecessary rewrite never happens;
///  2. otherwise a mapping this client was given before is reused, which is
///     what makes a NAT consistent enough for protocols that carry addresses;
///  3. only then is a fresh address picked and a free port searched for.
/// A random request skips the first two steps entirely, which is the whole
/// point of asking for randomness.
/// # C: O(NAT_MAX_ATTEMPTS · bucket length)
pub fn get_unique_tuple<E: NatEnv>(orig: &Tuple, r: &NatRange, manip: u8, env: &E)
    -> Option<Tuple>
{
    if manip == NF_NAT_MANIP_SRC && !r.random() {
        if in_range(orig, r, manip) && !env.tuple_taken(orig) {
            return Some(*orig);
        }
        if let Some(prior) = env.find_appropriate_src(orig, r) {
            if !env.tuple_taken(&prior) { return Some(prior); }
        }
    }

    let mut t = *orig;
    if r.flags & NF_NAT_RANGE_NETMAP != 0 {
        let mapped = netmap_addr(manip_addr(&t, manip), r, t.l3num);
        set_manip_addr(&mut t, manip, mapped);
    } else {
        let picked = pick_addr(&t, r, manip);
        set_manip_addr(&mut t, manip, picked);
    }

    if !r.random() {
        if r.proto_specified() {
            let (lo, hi) = r.ordered_ports();
            if r.flags & NF_NAT_RANGE_PROTO_OFFSET == 0
                && port_in_range(&t, r, manip)
                && (lo == hi || !env.tuple_taken(&t))
            { return Some(t); }
        } else if !env.tuple_taken(&t) {
            return Some(t);
        }
    }

    unique_tuple(&t, r, manip, env)
}
