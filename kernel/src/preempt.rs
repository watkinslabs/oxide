// Preempt-on-IRQ-exit shim per `13§9` / `22§4`.
//
// The timer ISR (and any other rescheduling event) sets
// NEED_RESCHED. Right before the IRQ epilogue (after EOI, before
// iretq/eret), the dispatcher calls `schedule_if_needed()` which
// drains the flag and, if set, picks the next task and switches.
//
// The actual save/restore protocol is split: the IRQ asm stub
// saves caller-save GPs onto the current task's kernel stack;
// `Context::switch` saves callee-save GPs into the saved-context
// of the prev task. Together they cover the full GP set.

use core::sync::atomic::{AtomicBool, Ordering};

/// Set by reschedule events (timer tick, wakeup outranks current,
/// preempt enable). Drained by `schedule_if_needed()` at IRQ exit.
pub static NEED_RESCHED: AtomicBool = AtomicBool::new(false);

/// Reads + clears the flag. The kthread polls this at safe points
/// (post-`hlt` wake) and calls `tick_yield()` when set. True
/// IRQ-exit preemption (drain + switch from the dispatcher tail)
/// requires every task to carry a synthetic iretq/eret frame on
/// its stack; tracked for a follow-up.
/// # C: O(1)
pub fn need_resched() -> bool {
    NEED_RESCHED.swap(false, Ordering::AcqRel)
}
