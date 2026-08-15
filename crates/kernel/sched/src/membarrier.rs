// `membarrier(2)` work fns.
//
// The expedited commands use the one generic cross-CPU call transport. It
// records completion per sender/target descriptor, so no membarrier-private
// IPI vector, pending bitset, or acknowledgement spin protocol can disagree
// with the rest of the kernel's cross-CPU work.
//
// THREE ROUND KINDS, because the barrier alone is not the whole contract:
// a plain round only orders memory; SYNC_CORE additionally makes every target
// discard already-fetched instructions, and RSEQ additionally aborts any
// restartable critical section a target is inside. `policy` decides which
// registration gates which kind, and `arch` owns the serializing instruction —
// both ungated, so the rules are hosted-tested rather than boot-tested.
//
// Callers run in syscall context and serialize overlapping rounds with the
// scheduler's sleeping mutex, never a private atomic spin owner.

// Module manifest:
//   `policy` — ungated decision logic: which READY bit gates which command,
//              when a round may be skipped, whether the caller is a target.
//   `arch`   — the core-serializing instruction and the return-to-user hook
//              that carries SYNC_CORE to threads that were off-CPU.

pub mod policy;
pub mod arch;
// The IPI protocol and the per-command work fns need the live runqueue, the
// cross-CPU poke and the running task's mm, none of which exist off-target.
// `policy` and `arch` are deliberately OUTSIDE that gate: a `#[cfg(test)]`
// block inside a target-gated module compiles out silently and reports "ok"
// having built nothing, so every rule worth testing lives in the two ungated
// children and this file keeps only the binding.
#[cfg(target_os = "oxide-kernel")] mod work;

pub use policy::{Kind, Ready, FLAG_RSEQ, FLAG_SYNC_CORE};
pub use arch::sync_core_before_usermode;
#[cfg(target_os = "oxide-kernel")]
pub use work::{global, global_expedited, private_expedited, register_global_expedited,
               register_private_expedited, registrations, service_global,
               service_private_mb, service_private_rseq, service_private_sync_core};
