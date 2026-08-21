// Terminal SMP stop shared by reboot, power-off, halt, and kexec.

use crate::CpuMask;

/// Other online CPUs that must stop before the calling CPU changes the
/// machine state. # C: O(words)
pub fn targets(online: CpuMask, me: usize) -> CpuMask { online.without(CpuMask::of(me)) }

/// Whether every requested CPU has entered the terminal stop handler.
/// # C: O(words)
pub fn converged(stopped: CpuMask, requested: CpuMask) -> bool {
    requested.without(stopped).is_empty()
}

/// One-second-equivalent clock-free wait. Terminal callers have already
/// masked their local timer, so elapsed monotonic time cannot drive this
/// boundary. # C: O(spin budget)
#[cfg(target_os = "oxide-kernel")]
const STOP_SPIN_BUDGET: u64 = 200_000_000;

/// Stop every other online CPU through the sole call-function transport.
/// Returns false after the bounded convergence wait; terminal callers still
/// proceed, matching the architecture shutdown contract. # C: O(spin budget)
#[cfg(target_os = "oxide-kernel")]
pub fn stop_other_cpus(me: usize) -> bool {
    let requested = targets(super::online_cpumask(), me);
    if requested.is_empty() { return true; }
    hal::smp_call::call_function_many(requested.as_words(), hal::smp_call::CallKind::Stop, 0, false);
    let mut spun = 0u64;
    while spun < STOP_SPIN_BUDGET {
        let stopped = CpuMask::from_words(&hal::smp_call::stopped_words());
        if converged(stopped, requested) { return true; }
        core::hint::spin_loop();
        spun += 1;
    }
    klog::announce_emergency("SMP: failed to stop secondary CPUs");
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mask(word: u64) -> CpuMask { CpuMask::from_words(&[word]) }

    #[test]
    fn caller_is_excluded_and_every_target_must_report_stopped() {
        let requested = targets(mask(0b1111), 2);
        assert_eq!(requested, mask(0b1011));
        assert!(!converged(mask(0b0011), requested));
        assert!(converged(mask(0b1011), requested));
        assert!(converged(mask(0b1111), requested), "unrequested stopped CPUs are harmless");
    }

    #[test]
    fn a_uniprocessor_machine_has_no_terminal_stop_targets() {
        let requested = targets(mask(1), 0);
        assert!(requested.is_empty());
        assert!(converged(mask(0), requested));
    }
}
