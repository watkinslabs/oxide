// Netfilter (nftables) hook bridge for the packet path. The netfilter
// crate installs its `eval` here (kmain wires `install_nf_hook`); the stack
// calls these at the PRE_ROUTING/LOCAL_IN (RX) and LOCAL_OUT/POST_ROUTING
// (TX) chokepoints so base chains actually enforce. Split out of stack.rs
// to keep that file under the 1000-line cap (08§7).

use core::sync::atomic::{AtomicPtr, Ordering};
#[cfg(any(test, feature = "hosted"))]
use core::sync::atomic::{AtomicBool, AtomicUsize};
use crate::pkt::Pkt;

/// Netfilter L3 family of the packet (Linux NFPROTO_*). Lets the nft expr
/// engine compute transport offsets + `meta nfproto`/`l4proto` per-family.
pub const NFPROTO_IPV4: u8 = 2;
pub const NFPROTO_IPV6: u8 = 10;

/// Netfilter verdict callback. Verdict u32: NF_DROP=0, NF_ACCEPT=1.
pub type NfHookFn = fn(hook_id: u32, pkt: &[u8], family: u8) -> u32;

static NF_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
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
pub(crate) fn nf_hook_eval(hook_id: u32, pkt: &[u8], family: u8) -> u32 {
    nf_hook_eval_in(0, hook_id, pkt, family)
}

/// Evaluate namespace-owned security policy before the legacy netfilter
/// callback. The ingress lease supplies the concrete namespace key.
pub(crate) fn nf_hook_eval_in(namespace: u64, hook_id: u32, pkt: &[u8], family: u8) -> u32 {
    let context = security::network::Context {
        namespace, family: family as u16, socket_type: 0, protocol: 0,
        operation: security::network::Operation::Packet,
    };
    if matches!(security::network::evaluate(context), security::network::Verdict::Deny) {
        return 0;
    }
    #[cfg(any(test, feature = "hosted"))]
    let _lease = loop {
        while NF_REPLACING.load(Ordering::Acquire) { hosted_yield(); }
        NF_ACTIVE.fetch_add(1, Ordering::AcqRel);
        if !NF_REPLACING.load(Ordering::Acquire) { break NfEvalLease; }
        NF_ACTIVE.fetch_sub(1, Ordering::AcqRel);
    };
    let raw = NF_HOOK.load(Ordering::Acquire);
    if raw.is_null() { return 1; /* NF_ACCEPT */ }
    // SAFETY: raw was installed via `install_nf_hook` with the documented `fn(u32, &[u8], u8) -> u32` signature.
    let f: NfHookFn = unsafe { core::mem::transmute(raw) };
    f(hook_id, pkt, family)
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
pub(crate) fn nf_output(p: &Pkt, family: u8) -> bool {
    nf_hook_eval(NF_INET_LOCAL_OUT, p.data(), family) != 0
        && nf_hook_eval(NF_INET_POST_ROUTING, p.data(), family) != 0
}
