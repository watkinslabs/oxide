// Linux timer/workqueue KPI module manifest.
// clock: jiffies/ktime/delay/schedule helpers.
// timer: timer_list/hrtimer helpers.
// work: workqueue/work_struct/delayed_work helpers.
// kthread: kthread lifecycle helpers.
// tasklet: tasklet compatibility helpers.

mod clock;
mod kthread;
mod tasklet;
mod timer;
mod types;
mod work;

pub(crate) const HZ: u32 = types::KPI_HZ as u32;

/// Register Linux timer/workqueue KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    work::init_runtime();
    use crate::symtab::export;
    export("jiffies", &clock::jiffies as *const _ as usize, false);
    export("jiffies_64", &clock::jiffies_64 as *const _ as usize, false);
    clock::export_symbols();
    timer::export_symbols();
    work::export_symbols();
    kthread::export_symbols();
    tasklet::export_symbols();
}

/// Install kernel time source used by Linux KPI time exports.
/// # C: O(1)
pub fn set_now_hook(f: clock::NowHook) {
    clock::set_now_hook(f);
}

/// Current jiffies with time-source publication applied. # C: O(1)
pub(crate) fn jiffies_now() -> u64 {
    clock::now_ns();
    clock::jiffies.load(core::sync::atomic::Ordering::Acquire)
}

/// Absolute monotonic deadline for a relative Linux jiffy timeout.
/// # C: O(1)
pub(crate) fn deadline_after_jiffies(timeout: u64) -> u64 {
    clock::now_ns().saturating_add(clock::jiffies_to_ns(timeout))
}

/// Sleep for a process-context PCI recovery delay. # C: O(1)
pub(crate) fn sleep_ms(ms: u32) { clock::sleep_ns(ms as u64 * 1_000_000); }

#[cfg(test)]
mod linux_time_tests;
