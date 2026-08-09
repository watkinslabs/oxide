// Cross-CPU call-function QUEUE PROTOCOL — the decision half, deliberately
// ungated so every ordering rule is host-unit-tested.
//
// The arch half (IPI send, the IDT vector, the handlers) is
// `#![cfg(target_os = "oxide-kernel")]` and x86-only; a test written there
// compiles out silently while `cargo test` still prints "ok". Everything
// that can be decided without a LAPIC is decided here instead: which CPUs a
// call targets, when a push must send an IPI, what order a drain runs
// entries in, and when a sender may consider its call complete — which is
// the ordering a free-after-converge depends on.
//
// Module manifest:
//   call_fn/queue.rs — the per-target queue, slot ownership, drain order.
//   call_fn/mask.rs  — target-set computation and stuck-wait bookkeeping.
//   call_fn/tests.rs — hosted tests (manifest of test modules).

pub mod mask;
pub mod queue;

pub use mask::{drop_unreachable, escalation_due, escalation_gap, targets_for};
pub use queue::{CallQueues, SlotState};

#[cfg(test)]
mod tests;
