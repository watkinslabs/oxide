use crate::{NFT_CHAIN_POLICY_DROP, active_generation, nft_expr};
use alloc::vec::Vec;

use crate::nft_expr::{Action, EvalCtx, uapi};
use crate::nft_expr::access::{CtAccess, FibEntry, FibKey, RouteAccess};
use conntrack::tuple::Tuple;

/// Netfilter verdict.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Verdict {
    Drop,
    Accept,
    Stolen,
    Queue(u16),
    Repeat,
    Stop,
}

/// A hook verdict and the packet mark left by its ruleset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalResult {
    pub verdict: Verdict,
    pub mark: u32,
    /// Effects in rule-evaluation order. The packet owner applies these after
    /// the walk; the interpreter does not own packet, route, or device state.
    pub actions: Vec<Action>,
}

impl Verdict {
    /// # C: O(1)
    pub fn as_u32(self) -> u32 {
        match self {
            Verdict::Drop => uapi::NF_DROP as u32,
            Verdict::Accept => uapi::NF_ACCEPT as u32,
            Verdict::Stolen => uapi::NF_STOLEN as u32,
            Verdict::Queue(q) => uapi::nf_queue_nr(q) as u32,
            Verdict::Repeat => uapi::NF_REPEAT as u32,
            Verdict::Stop => uapi::NF_STOP as u32,
        }
    }

    /// Verdict a rule's absolute code names. # C: O(1)
    pub fn from_code(code: i32) -> Option<Self> {
        Some(match code & uapi::NF_VERDICT_MASK {
            uapi::NF_DROP => Verdict::Drop,
            uapi::NF_ACCEPT => Verdict::Accept,
            uapi::NF_STOLEN => Verdict::Stolen,
            uapi::NF_QUEUE => Verdict::Queue(uapi::nf_verdict_qnum(code)),
            uapi::NF_REPEAT => Verdict::Repeat,
            uapi::NF_STOP => Verdict::Stop,
            _ => return None,
        })
    }
}

/// Evaluate the immutable ruleset generation published for `hook_id`.
/// # C: O(N_chains × N_rules × N_exprs)
pub fn eval(hook_id: u32, pkt: &[u8], family: u8) -> Verdict {
    eval_in(0, hook_id, pkt, family)
}

/// Evaluate one network namespace's immutable ruleset generation.
/// # C: O(log N_namespaces + N_chains × N_rules × N_exprs)
pub fn eval_in(namespace: u64, hook_id: u32, pkt: &[u8], family: u8) -> Verdict {
    eval_in_with_mark(namespace, hook_id, pkt, family, 0).verdict
}

/// Evaluate one hook while retaining nft's mutable packet mark. # C: O(N rules)
pub fn eval_in_with_mark(namespace: u64, hook_id: u32, pkt: &[u8], family: u8,
                         mark: u32) -> EvalResult {
    let input = crate::eval_context::Input::bare(namespace, hook_id, pkt, family, mark);
    eval_context(&input)
}

/// Evaluate one hook from the live packet-buffer and hook ownership. # C: O(N rules)
pub fn eval_hook(input: &net::stack::NfHookCtx<'_>) -> EvalResult {
    let input = crate::eval_context::Input::from_hook(input);
    eval_context(&input)
}

struct LiveCt<'a> {
    conn: Option<&'a conntrack::Conn>,
    info: u8,
    dir: u8,
    now: u64,
}

struct LiveRoute<'a> {
    input: &'a crate::eval_context::Input<'a>,
}

impl RouteAccess for LiveRoute<'_> {
    fn nexthop4(&self) -> Option<[u8; 4]> {
        if self.input.family != crate::nft_expr::uapi::NFPROTO_IPV4 { return None; }
        let b = self.input.pkt.get(16..20)?;
        let dst = net::addr::Ipv4Addr::new(b[0], b[1], b[2], b[3]);
        let route = net::global_stack().routes.lookup_result_mark_in(
            self.input.namespace, dst, self.input.mark).ok()?;
        Some(net::route::RouteRecord::next_hop_for(route.gateway, dst).octets())
    }
    fn nexthop6(&self) -> Option<[u8; 16]> {
        if self.input.family != crate::nft_expr::uapi::NFPROTO_IPV6 { return None; }
        let dst = net::addr::Ipv6Addr(self.input.pkt.get(24..40)?.try_into().ok()?);
        let route = net::global_stack().routes6.lookup_policy_mark_in(
            self.input.namespace, dst, net::global_stack().policy_rules(), self.input.mark)?;
        Some(net::route6::next_hop6_for(route.gateway, dst).0)
    }
    fn tcpmss(&self) -> Option<u16> {
        let dst = if self.input.family == crate::nft_expr::uapi::NFPROTO_IPV6 {
            net::addr::IpAddr::V6(net::addr::Ipv6Addr(self.input.pkt.get(24..40)?.try_into().ok()?))
        } else {
            let b = self.input.pkt.get(16..20)?;
            net::addr::IpAddr::V4(net::addr::Ipv4Addr::new(b[0], b[1], b[2], b[3]))
        };
        let mtu = match dst {
            net::addr::IpAddr::V4(a) => net::global_stack().routes.lookup_result_mark_in(
                self.input.namespace, a, self.input.mark).ok()
                .and_then(|r| net::global_stack().ifaces.lookup_in_ns(r.iface, self.input.namespace))
                .map(|d| d.mtu()),
            net::addr::IpAddr::V6(a) => net::global_stack().routes6.lookup_policy_mark_in(
                self.input.namespace, a, net::global_stack().policy_rules(), self.input.mark)
                .and_then(|r| net::global_stack().ifaces.lookup_in_ns(r.iface, self.input.namespace))
                .map(|d| d.mtu()),
        }?;
        Some(mtu.saturating_sub(if self.input.family == crate::nft_expr::uapi::NFPROTO_IPV6 { 60 } else { 40 }) as u16)
    }
    fn src_addr(&self) -> Option<conntrack::tuple::InetAddr> {
        if self.input.family == crate::nft_expr::uapi::NFPROTO_IPV6 {
            let dst = net::addr::Ipv6Addr(self.input.pkt.get(24..40)?.try_into().ok()?);
            let route = net::global_stack().routes6.lookup_policy_mark_in(
                self.input.namespace, dst, net::global_stack().policy_rules(), self.input.mark)?;
            return route.src_hint.map(|addr| conntrack::tuple::InetAddr::v6(addr.0));
        }
        let b = self.input.pkt.get(16..20)?;
        let dst = net::addr::Ipv4Addr::new(b[0], b[1], b[2], b[3]);
        let route = net::global_stack().routes.lookup_result_mark_in(
            self.input.namespace, dst, self.input.mark).ok()?;
        route.src_hint.map(|addr| conntrack::tuple::InetAddr::v4(addr.octets()))
    }
    fn fib(&self, key: &FibKey) -> Option<FibEntry> {
        let stack = net::global_stack();
        let (iface, kind) = match key.family {
            crate::nft_expr::uapi::NFPROTO_IPV4 => {
                let dst = net::addr::Ipv4Addr::from_u32(key.addr.as_v4_u32());
                let record = stack.routes.lookup_record_mark_in(self.input.namespace, dst, key.mark)?;
                (record.route.iface, record.kind as u32)
            }
            _ => return None,
        };
        let index = stack.ifaces.ifindex_in_ns(iface, self.input.namespace)?;
        let dev = stack.ifaces.lookup_in_ns(iface, self.input.namespace)?;
        let mut name = [0u8; crate::nft_expr::limits::IFNAMSIZ];
        let bytes = dev.name().as_bytes();
        let n = bytes.len().min(name.len().saturating_sub(1));
        name[..n].copy_from_slice(&bytes[..n]);
        Some(FibEntry { oif: Some(index), oifname: name, addrtype: kind })
    }
}

impl CtAccess for LiveCt<'_> {
    fn ctinfo(&self) -> u8 { self.info }
    fn attached(&self) -> bool { self.conn.is_some() }
    fn status(&self) -> u32 { self.conn.map_or(0, conntrack::Conn::status) }
    fn mark(&self) -> u32 { self.conn.map_or(0, |c| c.mark.load(core::sync::atomic::Ordering::Acquire)) }
    fn set_mark(&self, value: u32) {
        if let Some(c) = self.conn { c.mark.store(value, core::sync::atomic::Ordering::Release); }
    }
    fn secmark(&self) -> u32 { self.conn.map_or(0, |c| c.secmark.load(core::sync::atomic::Ordering::Acquire)) }
    fn set_secmark(&self, value: u32) {
        if let Some(c) = self.conn { c.secmark.store(value, core::sync::atomic::Ordering::Release); }
    }
    fn expiration_ms(&self) -> u32 {
        self.conn.map_or(0, |c| c.expires_in(self.now).saturating_mul(1000) as u32)
    }
    fn helper(&self, out: &mut [u8]) -> bool {
        let Some(c) = self.conn else { return false; };
        let helper = c.helper.lock();
        let Some(name) = helper.as_ref() else { return false; };
        let n = name.len().min(out.len());
        out[..n].copy_from_slice(&name.as_bytes()[..n]);
        true
    }
    fn counters(&self, dir: u8) -> (u64, u64) {
        self.conn.and_then(|c| c.counters.get(dir as usize)).map_or((0, 0), |x| x.read())
    }
    fn tuple(&self, dir: u8) -> Option<Tuple> {
        self.conn.map(|c| *c.tuple(if dir == conntrack::uapi::IP_CT_DIR_MAX as u8 {
            self.dir
        } else { dir }))
    }
    fn zone(&self) -> u16 { self.conn.map_or(0, |c| c.orig.zone) }
    fn id(&self) -> u32 { self.conn.map_or(0, |c| c.id as u32) }
    fn offloadable(&self) -> bool {
        self.conn.is_some_and(|c| {
            let status = c.status();
            status & (conntrack::uapi::IPS_CONFIRMED | conntrack::uapi::IPS_SEEN_REPLY
                | conntrack::uapi::IPS_ASSURED | conntrack::uapi::IPS_OFFLOAD) ==
                (conntrack::uapi::IPS_CONFIRMED | conntrack::uapi::IPS_SEEN_REPLY
                    | conntrack::uapi::IPS_ASSURED)
                && c.helper.lock().is_none()
        })
    }
}

fn eval_context(input: &crate::eval_context::Input<'_>) -> EvalResult {
    let namespace = input.namespace;
    let hook_id = input.hook_id;
    let pkt = input.pkt;
    let family = input.family;
    let mut mark = input.mark;
    let live_ct = LiveCt { conn: input.ct, info: input.ctinfo, dir: input.ct_dir,
                           now: input.timestamp_ns / 1_000_000_000 };
    let live_route = LiveRoute { input };
    let Some(generation) = active_generation(hook_id) else {
        return EvalResult { verdict: Verdict::Accept, mark, actions: Vec::new() };
    };
    let Some(state) = generation.namespace(namespace) else {
        return EvalResult { verdict: Verdict::Accept, mark, actions: Vec::new() };
    };
    let Some(hook) = state.hooks.iter().find(|hook| hook.id == hook_id) else {
        return EvalResult { verdict: Verdict::Accept, mark, actions: Vec::new() };
    };
    let mut actions = Vec::new();
    debug_assert!(hook.chains.windows(2).all(|chains| chains[0].priority <= chains[1].priority));
    for chain in hook.chains.iter().filter(|chain| chain.table_family == family) {
        let mut chain_verdict = None;
        for rule in &chain.rules {
            let lookup = |set_id: Option<usize>, _set_name: &str, register: &[u8]| {
                state.set_contains(set_id.expect("compiled lookup has a set id"), register)
            };
            let mut ctx = EvalCtx::new(pkt, family, &rule.states);
            input.populate(&mut ctx, mark);
            if input.ct_available { ctx.ct = Some(&live_ct); }
            if input.live { ctx.route = Some(&live_route); }
            ctx.set_lookup = Some(&lookup);
            let verdict = nft_expr::run_rule_ctx(&rule.exprs, &mut ctx);
            mark = ctx.mark;
            actions.extend(ctx.actions);
            if ctx.packets != 0 { rule.counter.bump(ctx.packets, ctx.bytes); }
            if let Some(decided) = Verdict::from_code(verdict.code) {
                chain_verdict = Some(decided);
                break;
            }
        }
        let verdict = chain_verdict.unwrap_or_else(|| match chain.policy {
            NFT_CHAIN_POLICY_DROP => Verdict::Drop,
            _ => Verdict::Accept,
        });
        if verdict != Verdict::Accept { return EvalResult { verdict, mark, actions }; }
    }
    EvalResult { verdict: Verdict::Accept, mark, actions }
}
