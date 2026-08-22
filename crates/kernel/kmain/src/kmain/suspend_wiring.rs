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

#[cfg(target_arch = "x86_64")]
fn persistent_clock_ns() -> Option<u64> {
    let seconds = hal_x86_64::read_rtc_unix_secs();
    (seconds != 0).then(|| seconds.saturating_mul(1_000_000_000))
}

#[cfg(target_arch = "aarch64")]
fn persistent_clock_ns() -> Option<u64> { firmware::fdt::rtc::unix_time_ns() }

/// Discover the architecture persistent clock and install its one timekeeper
/// reader before realtime is seeded. ARM must do this after FDT retention and
/// MMU/PMM setup because PL031 is an owned device-MMIO mapping.
/// # C: O(struct_block_size + mapped pages)
/// # Ctx: early boot CPU
pub fn init_persistent_clock() {
    #[cfg(target_arch = "aarch64")]
    if !firmware::fdt::rtc::init() { return; }
    let _ = timekeeper::suspend::set_persistent_clock(persistent_clock_ns);
}

/// A device-model refusal, recorded and translated. Every phase that can fail
/// funnels through here so the name is captured exactly once, at the point of
/// failure, before the unwind starts overwriting driver state.
fn refused() -> power::Error {
    if let Some(name) = drv::pm::dpm_failed_device() { STATS.save_failed_dev(&name); }
    power::Error::Busy
}

/// Start one device transition and run its common prepare phase.
/// # C: O(N_devices)
/// # Sleeps: driver-defined
pub fn devices_prepare(transition: drv::PmTransition) -> power::KResult<()> {
    cpufreq::suspend();
    drv::pm::dpm_set_transition(transition);
    match drv::pm::dpm_prepare() {
        Ok(()) => Ok(()), Err(_) => { cpufreq::resume(); Err(refused()) }
    }
}
/// Run the selected transition's normal-depth down callbacks. # C: O(N_devices)
pub fn devices_suspend() -> power::KResult<()> { drv::pm::dpm_suspend().map_err(|_| refused()) }
/// Run the selected transition's late down callbacks. # C: O(N_devices)
pub fn devices_late() -> power::KResult<()> { drv::pm::dpm_suspend_late().map_err(|_| refused()) }
fn arm_wake_irqs() {
    for device in drv::devices() {
        if !device.may_wakeup() { continue; }
        if let Some(irq) = device.wake_irq() { let _ = arch_irq::irq_set_irq_wake(irq, true); }
    }
}

fn disarm_wake_irqs() {
    for device in drv::devices() {
        if !device.may_wakeup() { continue; }
        if let Some(irq) = device.wake_irq() { let _ = arch_irq::irq_set_irq_wake(irq, false); }
    }
}

/// Run the selected transition's noirq callbacks after masking device IRQs.
/// # C: O(N_devices + N_wake_devices)
/// # Ctx: IRQ-off
pub fn devices_noirq() -> power::KResult<()> {
    use power::hibernate::log::{self, NoirqPhase};
    log::noirq_phase(NoirqPhase::WakeBegin);
    arm_wake_irqs();
    log::noirq_phase(NoirqPhase::WakeEnd);
    log::noirq_phase(NoirqPhase::IrqBegin);
    arch_irq::suspend_device_irqs();
    log::noirq_phase(NoirqPhase::IrqEnd);
    log::noirq_phase(NoirqPhase::DevicesBegin);
    if drv::pm::dpm_suspend_noirq().is_ok() {
        log::noirq_phase(NoirqPhase::DevicesEnd);
        return Ok(());
    }
    log::noirq_phase(NoirqPhase::DevicesEnd);
    arch_irq::resume_device_irqs();
    disarm_wake_irqs();
    Err(refused())
}

/// Undo the selected transition's noirq phase. # C: O(N_devices + N_wake_devices)
/// # Ctx: IRQ-off
pub fn devices_resume_noirq() {
    drv::pm::dpm_resume_noirq();
    arch_irq::resume_device_irqs();
    disarm_wake_irqs();
}
/// Run the selected transition's early up callbacks. # C: O(N_devices)
pub fn devices_resume_early() { drv::pm::dpm_resume_early(); }
/// Run the selected transition's normal-depth up callbacks. # C: O(N_devices)
pub fn devices_resume() { drv::pm::dpm_resume(); }
/// Complete the selected transition and restore cpufreq policy. # C: O(N_devices)
pub fn devices_complete() { drv::pm::dpm_complete(); cpufreq::resume(); }

fn suspend_prepare() -> power::KResult<()> { devices_prepare(drv::PmTransition::Suspend) }

/// Freeze userspace tasks for a system transition. # C: O(N_tasks * rounds)
/// # Sleeps: yes
pub fn users_freeze() -> power::KResult<()> { power::suspend::freezer_walk::freeze_processes() }
/// Thaw all tasks held by system sleep. # C: O(N_tasks)
pub fn users_thaw() { power::suspend::freezer_walk::thaw_processes(); }
/// Freeze freezable kernel threads. # C: O(N_tasks * rounds)
/// # Sleeps: yes
pub fn kernel_threads_freeze() -> power::KResult<()> {
    power::suspend::freezer_walk::freeze_kernel_threads()
}
/// Thaw freezable kernel threads without thawing userspace. # C: O(N_tasks)
pub fn kernel_threads_thaw() { power::suspend::freezer_walk::thaw_kernel_threads(); }

/// Disable and drain usermode helpers. # C: O(timeout)
/// # Sleeps: yes
pub fn helpers_disable() -> power::KResult<()> {
    if umh::usermodehelper_disable() == 0 { Ok(()) } else { Err(power::Error::Again) }
}
/// Re-enable usermode helpers. # C: O(1)
pub fn helpers_enable() { umh::usermodehelper_enable(); }

/// Exclude canonical device registry mutation for a power transaction.
/// # C: O(contention)
/// # Sleeps: yes
pub fn hotplug_lock() -> drv::model::HotplugGuard { drv::model::freeze_hotplug() }

/// Flush framebuffer-console damage and block new per-CPU flush publications.
/// UART/polled diagnostics remain available while the device graph is down.
/// # C: O(console damage + NR_CPUS)
fn console_suspend() { let _ = klog::console_pm::run_if_suspend_enabled(fbcon::kernel::console_suspend); }

/// Re-enable framebuffer-console deferred output after device recovery.
/// # C: O(1)
fn console_resume() { let _ = klog::console_pm::run_if_suspend_enabled(fbcon::kernel::console_resume); }

/// Install the device-model half of the sequence and register the interrupt
/// controllers' core callbacks.
/// # C: O(1)
/// # Ctx: boot path, single-CPU
pub fn init() {
    arch_irq::pm::register();
    power::suspend::boot::set_cpu_hooks(disable_secondary_cpus, enable_secondary_cpus);
    power::suspend::syscore::register_syscore(&TIMEKEEPING_SYSCORE);
    power::suspend::boot::set_device_hooks(power::suspend::boot::DeviceHooks {
        console_suspend: Some(console_suspend),
        console_resume: Some(console_resume),
        dpm_prepare: Some(suspend_prepare),
        dpm_suspend: Some(devices_suspend),
        dpm_suspend_late: Some(devices_late),
        dpm_suspend_noirq: Some(devices_noirq),
        dpm_resume_noirq: Some(devices_resume_noirq),
        dpm_resume_early: Some(devices_resume_early),
        dpm_resume: Some(devices_resume),
        dpm_complete: Some(devices_complete),
    });
}

/// Take every secondary through the architecture's reversible hotplug path.
/// # C: O(N CPUs + IPI/firmware transitions)
fn disable_secondary_cpus() -> power::KResult<()> {
    #[cfg(target_arch = "x86_64")]
    let ok = {
        // Linux x86 hibernation uses freeze_secondary_cpus(0): CPU0 is the
        // surviving processor and therefore owns the captured continuation.
        // Move this syscall's coordinator there without changing its saved
        // user/cpuset affinity, and hold that transient scheduler pin until
        // the matching online pass completes.
        use hal::CpuOps;
        let cpu = hal_x86_64::X86CpuOps::current_cpu();
        let current = sched::live::current();
        let idle = current.is_some_and(|t| matches!(t.sched_class(), sched::SchedClass::Idle));
        let pinned = sched::live::pin_current_to_cpu(0);
        power::hibernate::log::cpu_coordinator(cpu, current.is_some(), idle, pinned);
        if !pinned { return Err(power::Error::Busy); }
        let down = arch_irq::smp_x86::disable_secondary_cpus();
        if !down { let _ = sched::live::unpin_current_cpu(); }
        down
    };
    #[cfg(target_arch = "aarch64")]
    let ok = {
        // The arm image contract records the boot PE's MPIDR and cold restore
        // enters on that same logical PE. Retain the coordinator there through
        // the complete down/up pair just as the x86 boot-CPU path does.
        use hal::CpuOps;
        let cpu = hal_aarch64::ArmCpuOps::current_cpu();
        let boot = cpu::logical_id_for_hardware(cpu::smp::boot_cpu_id()).unwrap_or(0);
        let current = sched::live::current();
        let idle = current.is_some_and(|t| matches!(t.sched_class(), sched::SchedClass::Idle));
        let pinned = sched::live::pin_current_to_cpu(boot);
        power::hibernate::log::cpu_coordinator(cpu, current.is_some(), idle, pinned);
        if !pinned { return Err(power::Error::Busy); }
        let down = arch_irq::smp_arm::disable_secondary_cpus();
        if !down { let _ = sched::live::unpin_current_cpu(); }
        down
    };
    if ok { Ok(()) } else { Err(power::Error::Busy) }
}

/// Restart the exact CPU set recorded by the matching down pass. # C: O(N CPUs)
fn enable_secondary_cpus() {
    #[cfg(target_arch = "x86_64")]
    {
        arch_irq::smp_x86::enable_secondary_cpus();
        hal::kassert!(sched::live::unpin_current_cpu(),
            "CPU thaw lost hibernation coordinator pin");
    }
    #[cfg(target_arch = "aarch64")]
    {
        arch_irq::smp_arm::enable_secondary_cpus();
        hal::kassert!(sched::live::unpin_current_cpu(),
            "CPU thaw lost hibernation coordinator pin");
    }
}

/// Stop every secondary CPU for an irreversible machine transition.
/// # C: O(one bounded terminal stop wait)
pub(crate) fn stop_secondary_cpus_terminal() {
    #[cfg(target_arch = "x86_64")]
    let me = { use hal::CpuOps; hal_x86_64::X86CpuOps::current_cpu() as usize };
    #[cfg(target_arch = "aarch64")]
    let me = { use hal::CpuOps; hal_aarch64::ArmCpuOps::current_cpu() as usize };
    let _ = cpu::smp::terminal_stop::stop_other_cpus(me);
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
