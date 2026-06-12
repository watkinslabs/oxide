// SO_ATTACH_BPF socket-filter runner bridge. The eBPF interpreter lives in the
// `security` crate, which net can't depend on, so kmain installs a runner fn
// pointer here; the UDP RX path calls `bpf_accept` per datagram. Split out of
// stack.rs (08§7 1000-line cap).

use core::sync::atomic::{AtomicPtr, Ordering};

/// `(insns, pkt) -> accept`. Returns true (accept) when no runner is installed.
pub type BpfFilterFn = fn(&[u8], &[u8]) -> bool;

static BPF_RUNNER: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the eBPF socket-filter runner. Idempotent. # C: O(1)
pub fn install_bpf_filter_runner(f: BpfFilterFn) {
    BPF_RUNNER.store(f as *mut (), Ordering::Release);
}

/// Run an attached filter on `pkt`; true = accept, false = drop. No runner
/// installed → accept. # C: O(prog)
pub(crate) fn bpf_accept(insns: &[u8], pkt: &[u8]) -> bool {
    let raw = BPF_RUNNER.load(Ordering::Acquire);
    if raw.is_null() { return true; }
    // SAFETY: raw was installed via `install_bpf_filter_runner` with the
    // documented `fn(&[u8], &[u8]) -> bool` signature.
    let f: BpfFilterFn = unsafe { core::mem::transmute(raw) };
    f(insns, pkt)
}
