// Scheduler→sync spinning-lock preemption bridge per `06§3.1`.

use super::{preempt_disable, preempt_enable_no_check};

/// The preempt pair every spinning lock in `sync` takes. The release half is
/// the no-check form: a spin-lock release is not a schedule point.
static SPINLOCK_PREEMPT: sync::PreemptOps = sync::PreemptOps {
    disable: preempt_disable,
    enable: preempt_enable_no_check,
};

/// Install the gate after per-CPU state is live and before the first schedule.
/// # C: O(1)
pub fn install_spinlock_gate() {
    #[cfg(feature = "debug-preempt")]
    sync::preempt_gate::set_debug_cpu_hook(super::this_cpu);
    sync::set_preempt_ops(&SPINLOCK_PREEMPT);
}
