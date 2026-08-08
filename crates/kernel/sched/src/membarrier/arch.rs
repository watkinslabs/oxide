// The core-serialization primitive behind
// `MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE`, and the return-to-user hook
// that carries the guarantee to threads that were NOT running when the barrier
// was issued.
//
// WHAT THE COMMAND PROMISES. Every thread of the calling process executes a
// core-serializing instruction — one that discards any instruction already
// fetched or decoded — before it next runs user code. A JIT rewrites a
// function, issues the command, and may then assume no thread can still be
// executing the old bytes out of a pipeline or instruction cache.
//
// THE TWO ARCHES REACH IT DIFFERENTLY, AND THE DIFFERENCE IS THE WHOLE POINT.
//   x86_64 — the fast return to user mode (`sysretq`) is NOT serializing, so
//     the guarantee has to be issued explicitly. The IPI does it on CPUs that
//     were running the mm; `sync_core_before_usermode` does it on the
//     context-switch tail for a thread that was off-CPU at barrier time. Any
//     instruction documented as serializing works; `cpuid` is chosen because
//     it is architecturally present on every x86_64 part, needs no feature
//     detection and no static-branch machinery, and this path runs once per
//     command rather than per switch of an unregistered mm. It is slower than
//     the dedicated serializing instruction on parts that have one — a cost,
//     not a semantic difference.
//   aarch64 — `eret` is itself a context synchronization event, so ANY return
//     to EL0 already discards prefetched instructions. Taking the barrier IPI
//     and returning is therefore sufficient on its own, and the
//     context-switch-tail hook has nothing left to do. That asymmetry is not
//     an oxide shortcut: the reference contract selects core-serialization
//     support on both arches but only wires a return-to-user hook on the one
//     whose user return is not already synchronizing.

/// Execute a core-serializing instruction on THIS CPU.
///
/// Called from the barrier IPI on every target of a SYNC_CORE round, and
/// inline on the calling CPU, which is always a target of such a round.
/// # C: O(1)
/// # Ctx: IRQ or process
pub fn sync_core() {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // `cpuid` leaf 0, executed purely for its architecturally-documented
        // serializing side effect; the result is discarded. Unprivileged, no
        // memory effects, and the intrinsic owns the register save/restore —
        // which is why it needs no `unsafe` here.
        let _ = core::arch::x86_64::__cpuid(0);
    }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        // SAFETY: `sync_core` issues `isb`, an unprivileged context
        // synchronization event with no memory or register effects.
        unsafe { core::arch::asm!("isb", options(nostack, preserves_flags)); }
    }
}

/// The context-switch-tail half of the SYNC_CORE guarantee: a thread that was
/// descheduled when the barrier ran took no IPI, so it serializes here instead,
/// immediately before it can reach user mode again.
///
/// `wanted` is the incoming mm's SYNC_CORE registration bit. A mm that never
/// registered pays nothing, which is why the bit is consulted rather than
/// serializing unconditionally.
///
/// No-op on aarch64: the `eret` that completes this return to EL0 is itself a
/// context synchronization event (see module head).
/// # C: O(1)
/// # Ctx: context-switch tail
pub fn sync_core_before_usermode(wanted: bool) {
    #[cfg(target_arch = "aarch64")]
    { let _ = wanted; }
    #[cfg(not(target_arch = "aarch64"))]
    { if wanted { sync_core(); } }
}
