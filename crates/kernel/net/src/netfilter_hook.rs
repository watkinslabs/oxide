// Netfilter (nftables) hook bridge for the packet path. The netfilter
// crate installs its `eval` here (kmain wires `install_nf_hook`); the stack
// calls these at the PRE_ROUTING/LOCAL_IN (RX) and LOCAL_OUT/POST_ROUTING
// (TX) chokepoints so base chains actually enforce. Split out of stack.rs
// to keep that file under the 1000-line cap (08§7).

use core::sync::atomic::{AtomicPtr, Ordering};
use crate::pkt::Pkt;

/// Netfilter verdict callback. Verdict u32: NF_DROP=0, NF_ACCEPT=1.
pub type NfHookFn = fn(hook_id: u32, pkt: &[u8]) -> u32;

static NF_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the netfilter bridge. Idempotent. # C: O(1)
pub fn install_nf_hook(f: NfHookFn) {
    NF_HOOK.store(f as *mut (), Ordering::Release);
}

/// Invoke the registered netfilter hook. Returns NF_ACCEPT (1) when no
/// hook is installed so the default-accept path still works without
/// netfilter wired. # C: O(1) when no hook; otherwise O(eval)
pub(crate) fn nf_hook_eval(hook_id: u32, pkt: &[u8]) -> u32 {
    let raw = NF_HOOK.load(Ordering::Acquire);
    if raw.is_null() { return 1; /* NF_ACCEPT */ }
    // SAFETY: raw was installed via `install_nf_hook` with the documented `fn(u32, &[u8]) -> u32` signature.
    let f: NfHookFn = unsafe { core::mem::transmute(raw) };
    f(hook_id, pkt)
}

// Netfilter hook ids (Linux `NF_INET_*`, uapi netfilter.h). Mirror
// `netfilter::hook`. PRE_ROUTING + LOCAL_IN gate the RX path; LOCAL_OUT +
// POST_ROUTING gate locally-generated TX. FORWARD has no traffic — this is
// a host stack with no IP forwarding path, so (as in Linux with forwarding
// off) the FORWARD chain is never traversed.
pub const NF_INET_PRE_ROUTING:  u32 = 0;
pub const NF_INET_LOCAL_IN:     u32 = 1;
pub const NF_INET_LOCAL_OUT:    u32 = 3;
pub const NF_INET_POST_ROUTING: u32 = 4;

/// Netfilter output path for a locally-generated IPv4 packet `p`: traverse
/// LOCAL_OUT then POST_ROUTING on the built L3 bytes. Returns `true` to
/// transmit (NF_ACCEPT), `false` when a base chain DROPs — the caller then
/// returns `Ok(())`, a silent drop matching Linux NF_DROP.
/// # C: O(eval) ×2
pub(crate) fn nf_output_ipv4(p: &Pkt) -> bool {
    nf_hook_eval(NF_INET_LOCAL_OUT, p.data()) != 0
        && nf_hook_eval(NF_INET_POST_ROUTING, p.data()) != 0
}
