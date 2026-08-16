// Joins the device model and the interrupt controllers to the suspend
// sequence (`32a§5` steps 4-12, `32a§7`).
//
// The two halves speak different error types on purpose: `drv` reports a
// driver-model failure and `power` reports a sleep-sequence failure, and
// neither crate can name the other's. This file is the one place the two meet,
// so a device that refuses is turned into the sequence's `EBUSY` and its name
// is recorded in the statistics — the reference records the failing device, and
// a suspend that unwinds without saying which driver refused is a bug report
// nobody can act on.

use power::suspend::stats::STATS;

/// A device-model refusal, recorded and translated. Every phase that can fail
/// funnels through here so the name is captured exactly once, at the point of
/// failure, before the unwind starts overwriting driver state.
fn refused() -> power::Error {
    if let Some(name) = drv::pm::dpm_failed_device() { STATS.save_failed_dev(&name); }
    power::Error::Busy
}

fn prepare() -> power::KResult<()> {
    drv::pm::dpm_set_transition(drv::pm::PmTransition::Suspend);
    drv::pm::dpm_prepare().map_err(|_| refused())
}
fn suspend() -> power::KResult<()> { drv::pm::dpm_suspend().map_err(|_| refused()) }
fn suspend_late() -> power::KResult<()> { drv::pm::dpm_suspend_late().map_err(|_| refused()) }
fn suspend_noirq() -> power::KResult<()> { drv::pm::dpm_suspend_noirq().map_err(|_| refused()) }

/// Install the device-model half of the sequence and register the interrupt
/// controllers' core callbacks.
/// # C: O(1)
/// # Ctx: boot path, single-CPU
pub fn init() {
    arch_irq::pm::register();
    power::suspend::syscore::register_syscore(&TIMEKEEPING_SYSCORE);
    power::suspend::boot::set_device_hooks(power::suspend::boot::DeviceHooks {
        console_suspend: None,
        console_resume: None,
        dpm_prepare: Some(prepare),
        dpm_suspend: Some(suspend),
        dpm_suspend_late: Some(suspend_late),
        dpm_suspend_noirq: Some(suspend_noirq),
        dpm_resume_noirq: Some(drv::pm::dpm_resume_noirq),
        dpm_resume_early: Some(drv::pm::dpm_resume_early),
        dpm_resume: Some(drv::pm::dpm_resume),
        dpm_complete: Some(drv::pm::dpm_complete),
    });
}

/// Timekeeping's core callbacks. It cannot register its own: `power` depends on
/// `timekeeper`, so the reverse edge would be a cycle.
static TIMEKEEPING_SYSCORE: power::suspend::syscore::SyscoreOps =
    power::suspend::syscore::SyscoreOps {
        name: "timekeeping",
        suspend: Some(timekeeping_suspend),
        resume: Some(timekeeping_resume),
        shutdown: None,
    };

/// Freeze the clock so no monotonic time passes while the machine sleeps.
/// # C: O(1)
/// # Ctx: IRQ-off, single-CPU
fn timekeeping_suspend() -> power::KResult<()> {
    timekeeper::suspend::timekeeping_suspend();
    Ok(())
}

/// Credit the sleep to the wall and boot clocks, leaving the monotonic one
/// where it was.
/// # C: O(1)
/// # Ctx: IRQ-off, single-CPU
fn timekeeping_resume() { let _ = timekeeper::suspend::timekeeping_resume(); }
