// Stopping the machine before the copy starts.
//
// The reference's `machine_shutdown()` in one sentence: every other CPU has to
// stop executing, and every interrupt source has to stop asserting, BEFORE a
// single destination page is written. Both for the same reason — the pages
// being overwritten include the ones another CPU is running out of, and the
// ones a device is about to DMA into.
//
// The decisions live here, ungated, so the target set and the convergence rule
// are host-checkable; the privileged half (the IPI, the mask writes, the halt)
// is in the per-arch module. This kernel already has one cross-CPU call
// mechanism, so the stop is a KIND on that queue rather than a second protocol
// beside it.

/// CPUs that must stop, given the online set and the CPU running the kexec.
///
/// The caller is excluded because it is the one that performs the relocation:
/// asking it to halt would stop the machine with the image un-copied.
/// # C: O(words)
pub fn stop_targets(online: cpu::CpuMask, me: usize) -> cpu::CpuMask {
    online.without(cpu::CpuMask::of(me))
}

/// Whether every target has reported itself stopped.
///
/// A target that never reports is not waited on forever. The reference gives
/// its stop a timeout and proceeds regardless, because the alternative is a
/// machine that hangs with a perfectly good image loaded — and it says so in
/// the log rather than silently.
/// # C: O(words)
pub fn converged(stopped: cpu::CpuMask, targets: cpu::CpuMask) -> bool {
    targets.without(stopped).is_empty()
}

/// CPUs still running when the wait gave up.
/// # C: O(words)
pub fn stragglers(stopped: cpu::CpuMask, targets: cpu::CpuMask) -> cpu::CpuMask {
    targets.without(stopped)
}

/// How long to wait for the other CPUs before relocating anyway, in
/// nanoseconds. The reference waits one second for its reboot IPI.
pub const STOP_TIMEOUT_NS: u64 = 1_000_000_000;

#[cfg(test)]
mod tests {
    use super::*;

    fn mask(word: u64) -> cpu::CpuMask { cpu::CpuMask::from_words(&[word]) }

    #[test]
    fn the_relocating_cpu_is_never_asked_to_halt() {
        assert_eq!(stop_targets(mask(0b1111), 0), mask(0b1110));
        assert_eq!(stop_targets(mask(0b1111), 2), mask(0b1011));
    }

    #[test]
    fn a_uniprocessor_machine_has_nothing_to_stop() {
        assert_eq!(stop_targets(mask(0b1), 0), mask(0));
        assert!(converged(mask(0), mask(0)));
    }

    #[test]
    fn convergence_needs_every_target_and_ignores_extras() {
        assert!(!converged(mask(0b0010), mask(0b0110)));
        assert!(converged(mask(0b0110), mask(0b0110)));
        // A CPU that stopped for some other reason is not a target and must
        // not make an incomplete stop look complete.
        assert!(converged(mask(0b1110), mask(0b0110)));
        assert_eq!(stragglers(mask(0b0010), mask(0b0110)), mask(0b0100));
    }

    #[test]
    fn an_out_of_range_cpu_index_never_clears_a_target() {
        // A CPU id past the mask width must not silently unmask bit 0.
        assert_eq!(stop_targets(mask(0b1111), 64), mask(0b1111));
    }
}

/// Spins to wait for the other CPUs before relocating anyway. Clock-free
/// because this runs after the tick has been masked, so there is no monotonic
/// source left to read.
#[cfg(target_os = "oxide-kernel")]
const STOP_SPIN_BUDGET: u64 = 200_000_000;

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
    let online = cpu::smp::online_cpumask();
    #[cfg(target_arch = "x86_64")]
    let me = { use hal::CpuOps; hal_x86_64::X86CpuOps::current_cpu() as usize };
    #[cfg(target_arch = "aarch64")]
    let me = { use hal::CpuOps; hal_aarch64::ArmCpuOps::current_cpu() as usize };
    let targets = stop_targets(online, me);
    if targets.is_empty() { return; }
    hal::smp_call::call_function_many(targets.as_words(), hal::smp_call::CallKind::Stop, 0, false);
    // Between the request and the convergence wait, because those are two
    // different ways for this to stop making progress and the log has to tell
    // them apart: the request itself can block on a queue another CPU is not
    // draining, and the wait can simply not converge.
    klog::announce_emergency("kexec: stop requested");
    let mut spun = 0u64;
    while spun < STOP_SPIN_BUDGET {
        if converged(cpu::CpuMask::from_words(&[hal::smp_call::stopped_mask()]), targets) { return; }
        core::hint::spin_loop();
        spun += 1;
    }
    klog::announce_emergency("kexec: some CPUs did not stop; relocating anyway");
}
