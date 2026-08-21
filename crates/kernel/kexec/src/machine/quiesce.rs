// Terminal CPU-stop policy is owned by `cpu::smp::terminal_stop`; kexec only
// supplies the architecture's current logical CPU.

/// Ask every other online CPU to halt, and wait — bounded — for them to say
/// they have.
///
/// The stop rides the kernel's one cross-CPU call queue rather than a private
/// vector. A second mechanism here would be a second opinion about which CPUs
/// have acknowledged, at the exact moment there is no way to reconcile them.
///
/// It does not wait forever. A CPU wedged with interrupts masked would
/// otherwise hang a machine that has a perfectly good image loaded; the
/// reference gives its stop a timeout for the same reason and says so in the
/// log.
#[cfg(target_os = "oxide-kernel")]
/// # C: O(spin budget)
pub fn stop_other_cpus() {
    #[cfg(target_arch = "x86_64")]
    let me = { use hal::CpuOps; hal_x86_64::X86CpuOps::current_cpu() as usize };
    #[cfg(target_arch = "aarch64")]
    let me = { use hal::CpuOps; hal_aarch64::ArmCpuOps::current_cpu() as usize };
    let _ = cpu::smp::terminal_stop::stop_other_cpus(me);
}
