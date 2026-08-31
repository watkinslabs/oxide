// Task method manifest: identity/thread-group ownership, diagnostics,
// construction/stack lifecycle, scheduling state, and accounting each live
// in a focused child module.
mod identity;
mod diagnostics;
#[cfg(feature = "debug-smp")]
pub(super) use diagnostics::{task_canary_head, task_canary_tail};
#[cfg(any(feature = "debug-smp", feature = "debug-stack-guard"))]
pub(super) use diagnostics::{TASK_STACK_GUARD, TASK_STACK_GUARD_BYTES,
    TASK_STACK_WATERMARK_OFF};
mod lifecycle;
mod state;
mod accounting;
mod personality;
