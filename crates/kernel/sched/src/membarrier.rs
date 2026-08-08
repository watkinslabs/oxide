// `membarrier(2)` work fns.
//
// WHAT THE EXPEDITED COMMANDS ACTUALLY NEED. Linux's `ipi_mb()` is nothing
// but `smp_mb()`: the ordering comes from the TARGET entering the kernel and
// executing a full barrier, not from a private vector. So the poke rides the
// existing cross-CPU resched IPI (`live::send_resched_ipi` — x86 `VEC_RESCHED`,
// arm `SGI 0`), which is already installed, already enabled on every PE, and
// already delivered through both dispatchers; each dispatcher calls `service()`
// on entry. A spurious `need_resched` on a target is the same cost Linux pays
// for every wake-up IPI, and this needs no new IDT stub / per-redistributor SGI
// enable — the two places an arch-lockstep gap would otherwise open.
//
// PROTOCOL (single in-flight, mirrors `arch-irq::tlb`):
//   sender: fence -> publish KIND -> publish PENDING(targets) -> IPI each ->
//           spin till 0 -> fence
//   target: IRQ entry -> `service()`: fence, do KIND's extra work, clear own bit
// The target's fence is ordered AFTER it observed the sender's `PENDING`
// store, which is ordered after the sender's pre-syscall user writes. That is
// exactly the (a)/(b)/(c) pairing the barrier scenarios require.
//
// THREE ROUND KINDS, because the barrier alone is not the whole contract:
// a plain round only orders memory; SYNC_CORE additionally makes every target
// discard already-fetched instructions, and RSEQ additionally aborts any
// restartable critical section a target is inside. `policy` decides which
// registration gates which kind, and `arch` owns the serializing instruction —
// both ungated, so the rules are hosted-tested rather than boot-tested.
//
// Callers run in syscall context with IRQs ON, so a target can always take the
// IPI; a second would-be sender spins on `OWNER` while calling `service()`, so
// it still ACKs the in-flight round and sender-vs-sender cannot deadlock.

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
               register_private_expedited, registrations, service};
