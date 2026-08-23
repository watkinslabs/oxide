// Netfilter (nftables) hook bridge for the packet path. The netfilter
// crate installs its `eval` here (kmain wires `install_nf_hook`); the stack
// calls these at the PRE_ROUTING/LOCAL_IN (RX) and LOCAL_OUT/POST_ROUTING
// (TX) chokepoints so base chains actually enforce. Split out of stack.rs
// to keep that file under the 1000-line cap (08§7).

extern crate alloc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, Ordering};
#[cfg(any(test, feature = "hosted"))]
use core::sync::atomic::{AtomicBool, AtomicUsize};
use crate::pkt::Pkt;
use crate::NetIfaceId;

/// Netfilter L3 family of the packet (Linux NFPROTO_*). Lets the nft expr
/// engine compute transport offsets + `meta nfproto`/`l4proto` per-family.
pub const NFPROTO_IPV4: u8 = 2;
pub const NFPROTO_IPV6: u8 = 10;

/// Netfilter result carried across an ingress hook.  Packet marks are routing
/// metadata: nft may update them at PRE_ROUTING, and policy routing consumes
/// the resulting value before deciding local input versus forwarding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NfHookResult {
    pub verdict: u32,
    pub mark: u32,
    pub actions: Vec<crate::netfilter_action::Action>,
    pub notrack: bool,
}

/// Live packet and hook ownership presented to one netfilter walk. The shape
/// retains the packet-buffer metadata and hook devices instead of reducing the
/// call to bytes that cannot answer nftables metadata lookups.
pub struct NfHookCtx<'a> {
    pub namespace: u64,
    pub hook_id: u32,
    pub pkt: &'a [u8],
    pub ll: &'a [u8],
    pub family: u8,
    pub mark: u32,
    pub priority: u32,
    pub ingress: Option<NetIfaceId>,
    pub egress: Option<NetIfaceId>,
    pub timestamp_ns: u64,
    pub ct: Option<&'a conntrack::Conn>,
    pub ct_available: bool,
    pub ctinfo: u8,
    pub ct_dir: u8,
    pub chain_min_priority: Option<i32>,
    pub chain_max_priority: Option<i32>,
}

impl<'a> NfHookCtx<'a> {
    /// Context for a received L3 packet at one hook. # C: O(1)
    pub const fn ingress(namespace: u64, hook_id: u32, pkt: &'a [u8], family: u8,
                         ingress: NetIfaceId, mark: u32) -> Self {
        Self { namespace, hook_id, pkt, ll: &[], family, mark, priority: 0,
            ingress: Some(ingress), egress: None, timestamp_ns: 0,
            ct: None, ct_available: false, ctinfo: conntrack::uapi::IP_CT_UNTRACKED, ct_dir: 0,
            chain_min_priority: None, chain_max_priority: None }
    }

    /// Context retaining one canonical packet buffer's metadata. # C: O(1)
    pub fn packet(namespace: u64, hook_id: u32, p: &'a Pkt, family: u8,
                  ingress: Option<NetIfaceId>) -> Self {
        let (ct, ct_available, ctinfo, ct_dir) = p.conntrack_state()
            .map(|(_, ct, info, dir)| (ct, true, info, dir))
            .unwrap_or((None, false, conntrack::uapi::IP_CT_UNTRACKED, 0));
        Self { namespace, hook_id, pkt: p.data(), ll: p.mac_frame().unwrap_or(&[]), family,
            mark: p.tx.mark, priority: p.tx.priority, ingress, egress: p.iface,
            timestamp_ns: p.timestamp_ns, ct, ct_available, ctinfo, ct_dir,
            chain_min_priority: None, chain_max_priority: None }
    }
}

impl NfHookResult {
    pub const ACCEPT: Self = Self { verdict: 1, mark: 0, actions: Vec::new(), notrack: false };
}

/// Netfilter callback. Verdict u32: NF_DROP=0, NF_ACCEPT=1.
pub type NfHookFn = fn(ctx: &NfHookCtx<'_>) -> NfHookResult;
pub type NfHookStageFn = fn(u64, u32, u8, Option<i32>, Option<i32>) -> bool;

static NF_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static NF_STAGE: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
#[cfg(any(test, feature = "hosted"))]
static NF_REPLACING: AtomicBool = AtomicBool::new(false);
#[cfg(any(test, feature = "hosted"))]
static NF_ACTIVE: AtomicUsize = AtomicUsize::new(0);

#[cfg(any(test, feature = "hosted"))]
struct NfEvalLease;

#[cfg(any(test, feature = "hosted"))]
impl Drop for NfEvalLease {
    fn drop(&mut self) { NF_ACTIVE.fetch_sub(1, Ordering::AcqRel); }
}

#[cfg(any(test, feature = "hosted"))]
fn hosted_yield() {
    #[cfg(target_os = "oxide-kernel")]
    core::hint::spin_loop();
    #[cfg(not(target_os = "oxide-kernel"))]
    std::thread::yield_now();
}

/// Install the netfilter bridge. Idempotent. # C: O(1)
pub fn install_nf_hook(f: NfHookFn) {
    #[cfg(not(any(test, feature = "hosted")))]
    NF_HOOK.store(f as *mut (), Ordering::Release);
    #[cfg(any(test, feature = "hosted"))]
    let _ = swap_nf_hook(Some(f));
}

/// Install the netfilter bridge and its compiled-chain stage predicate.
pub fn install_nf_hook_with_stages(f: NfHookFn, stage: NfHookStageFn) {
    install_nf_hook(f);
    NF_STAGE.store(stage as *mut (), Ordering::Release);
}

#[cfg(any(test, feature = "hosted"))]
/// Replace the process callback after in-flight evaluations quiesce. # C: O(wait)
pub(crate) fn swap_nf_hook(hook: Option<NfHookFn>) -> Option<NfHookFn> {
    while NF_REPLACING.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
        hosted_yield();
    }
    while NF_ACTIVE.load(Ordering::Acquire) != 0 { hosted_yield(); }
    let raw = NF_HOOK.swap(hook.map_or(core::ptr::null_mut(), |hook| hook as *mut ()),
        Ordering::AcqRel);
    NF_REPLACING.store(false, Ordering::Release);
    if raw.is_null() { None } else {
        // SAFETY: `NF_HOOK` only stores callbacks with the `NfHookFn` signature.
        Some(unsafe { core::mem::transmute::<*mut (), NfHookFn>(raw) })
    }
}

/// Invoke the registered netfilter hook for an `family` (NFPROTO_*) packet.
/// Returns NF_ACCEPT (1) when no hook is installed so the default-accept
/// path still works without netfilter wired.
/// # C: O(1) when no hook; otherwise O(eval)
#[cfg(any(test, feature = "hosted"))]
pub(crate) fn nf_hook_eval(hook_id: u32, pkt: &[u8], family: u8) -> u32 {
    nf_hook_eval_in(0, hook_id, pkt, family).verdict
}

/// Evaluate namespace-owned security policy before the legacy netfilter
/// callback. The ingress lease supplies the concrete namespace key.
pub(crate) fn nf_hook_eval_in(namespace: u64, hook_id: u32, pkt: &[u8], family: u8) -> NfHookResult {
    let ctx = NfHookCtx { namespace, hook_id, pkt, ll: &[], family, mark: 0, priority: 0,
        ingress: None, egress: None, timestamp_ns: 0,
        ct: None, ct_available: false, ctinfo: conntrack::uapi::IP_CT_UNTRACKED, ct_dir: 0,
        chain_min_priority: None, chain_max_priority: None };
    nf_hook_eval_ctx(&ctx)
}

/// Evaluate one hook with the live packet and hook ownership retained. # C: O(eval)
pub(crate) fn nf_hook_eval_ctx(ctx: &NfHookCtx<'_>) -> NfHookResult {
    let context = security::network::Context::op(ctx.namespace, ctx.family as u16, 0, 0,
        security::network::Operation::Packet);
    if matches!(security::network::evaluate(context), security::network::Verdict::Deny) {
        return NfHookResult { verdict: 0, mark: 0, actions: Vec::new(), notrack: false };
    }
    #[cfg(any(test, feature = "hosted"))]
    let _lease = loop {
        while NF_REPLACING.load(Ordering::Acquire) { hosted_yield(); }
        NF_ACTIVE.fetch_add(1, Ordering::AcqRel);
        if !NF_REPLACING.load(Ordering::Acquire) { break NfEvalLease; }
        NF_ACTIVE.fetch_sub(1, Ordering::AcqRel);
    };
    let raw = NF_HOOK.load(Ordering::Acquire);
    if raw.is_null() { return NfHookResult::ACCEPT; }
    // SAFETY: raw was installed via `install_nf_hook` with the documented
    // namespace-qualified `NfHookFn` signature.
    let f: NfHookFn = unsafe { core::mem::transmute(raw) };
    f(ctx)
}

/// Evaluate an ingress/forward hook and consume its actions on the packet
/// owner before the next layer observes it. # C: O(eval + actions)
pub(crate) fn nf_hook_packet_in(namespace: u64, hook_id: u32, p: &mut Pkt,
                                 family: u8, iface: Option<NetIfaceId>, mark: u32)
                                 -> NfHookResult {
    let tracking_hook = hook_id == NF_INET_PRE_ROUTING || hook_id == NF_INET_LOCAL_OUT;
    let mut mark = mark;
    let mut notrack = false;
    if tracking_hook {
        let raw = nf_hook_packet_stage(namespace, hook_id, p, family, iface, mark,
                                       None, Some(-200));
        if raw.verdict == 0 || apply_actions(p, family, hook_id, &raw.actions).is_err() {
            return NfHookResult { verdict: 0, mark: raw.mark, actions: Vec::new(), notrack: raw.notrack };
        }
        mark = raw.mark;
        notrack = raw.notrack;
        p.tx.mark = mark;
        if notrack {
            let table = crate::global_stack().conntrack_in(namespace);
            p.set_conntrack_state(table, None, conntrack::uapi::IP_CT_UNTRACKED, 0);
        } else if !crate::global_stack().track_conntrack(namespace, p, family) {
            return NfHookResult { verdict: 0, mark, actions: Vec::new(), notrack };
        }
    }
    p.tx.mark = mark;
    let result = nf_hook_packet_stage(namespace, hook_id, p, family, iface, mark,
                                      tracking_hook.then_some(-200), None);
    if result.verdict == 0 || apply_actions(p, family, hook_id, &result.actions).is_err() {
        return NfHookResult { verdict: 0, mark: result.mark, actions: Vec::new(), notrack: notrack || result.notrack };
    }
    p.tx.mark = result.mark;
    if (hook_id == NF_INET_LOCAL_IN || hook_id == NF_INET_POST_ROUTING)
        && !p.confirm_conntrack() { return NfHookResult { verdict: 0, mark: result.mark, actions: Vec::new(), notrack: notrack || result.notrack }; }
    NfHookResult { notrack: notrack || result.notrack, ..result }
}

fn nf_hook_packet_stage(namespace: u64, hook_id: u32, p: &Pkt, family: u8,
                        iface: Option<NetIfaceId>, mark: u32,
                        min_priority: Option<i32>, max_priority: Option<i32>) -> NfHookResult {
    let stage = NF_STAGE.load(Ordering::Acquire);
    if stage.is_null() {
        // The legacy bridge has no way to advertise compiled chain ranges;
        // retain its single callback observation and reserve raw splitting
        // for install_nf_hook_with_stages.
        if max_priority.is_some() { return NfHookResult::ACCEPT; }
    } else {
        // SAFETY: NF_STAGE is written only by install_nf_hook_with_stages with
        // the documented stage predicate signature.
        let has_stage: NfHookStageFn = unsafe { core::mem::transmute(stage) };
        if !has_stage(namespace, hook_id, family, min_priority, max_priority) {
            return NfHookResult::ACCEPT;
        }
    }
    let mut ctx = NfHookCtx::packet(namespace, hook_id, p, family, iface);
    ctx.mark = mark;
    ctx.chain_min_priority = min_priority;
    ctx.chain_max_priority = max_priority;
    nf_hook_eval_ctx(&ctx)
}

// Netfilter hook ids (Linux `NF_INET_*`, uapi netfilter.h). Mirror
// `netfilter::hook`. PRE_ROUTING gates RX before route selection; LOCAL_IN
// gates local delivery; FORWARD + POST_ROUTING gate router-mode transit;
// LOCAL_OUT + POST_ROUTING gate locally-generated TX.
pub const NF_INET_PRE_ROUTING:  u32 = 0;
pub const NF_INET_LOCAL_IN:     u32 = 1;
pub const NF_INET_FORWARD:      u32 = 2;
pub const NF_INET_LOCAL_OUT:    u32 = 3;
pub const NF_INET_POST_ROUTING: u32 = 4;

/// Netfilter output path for a locally-generated L3 packet `p` of `family`
/// (NFPROTO_IPV4 / NFPROTO_IPV6): traverse LOCAL_OUT then POST_ROUTING on
/// the built L3 bytes. Returns `true` to transmit (NF_ACCEPT), `false` when
/// a base chain DROPs — the caller then returns `Ok(())`, a silent drop
/// matching Linux NF_DROP.
/// # C: O(eval) ×2
pub(crate) fn nf_output(p: &mut Pkt, family: u8) -> bool {
    nf_output_in(crate::netdev::current_net_ns(), p, family)
}

/// Netfilter output under the retained socket namespace. # C: O(eval) ×2
pub(crate) fn nf_output_in(namespace: u64, p: &mut Pkt, family: u8) -> bool {
    let context = security::network::Context::op(namespace, family as u16, 0, 0,
        security::network::Operation::Send);
    if matches!(security::network::evaluate(context), security::network::Verdict::Deny) {
        return false;
    }
    let mark = p.tx.mark;
    let local = nf_hook_packet_in(namespace, NF_INET_LOCAL_OUT, p, family, None, mark);
    if local.verdict == 0 { return false; }
    let mark = p.tx.mark;
    let post = nf_hook_packet_in(namespace, NF_INET_POST_ROUTING, p, family, None, mark);
    post.verdict != 0
}

fn apply_actions(p: &mut Pkt, family: u8, hook: u32,
                 actions: &[crate::netfilter_action::Action]) -> Result<(), ()> {
    for action in actions {
        action.apply_at(p, family, hook).map_err(|_| ())?;
    }
    if let Some((_, Some(conn), _, dir)) = p.conntrack_state_owned() {
        crate::netfilter_action::apply_conntrack_packet(p, conn, dir, family, hook)
            .map_err(|_| ())?;
    }
    Ok(())
}
