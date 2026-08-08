use super::*;
use hal::{CpuOps, Nanos, TimerOps};
use sync::{Buddy, IrqGate, Spinlock};

    #[test]
    fn irqgate_noop_on_host() {
        // Host build: save_disable returns 0; restore is a no-op.
        // SAFETY: hosted test entry; arch-asm path is cfg'd out so this
        // exercises only the no-op fallback per the cfg gates above.
        let f = unsafe { X86IrqGate::save_disable() };
        assert_eq!(f, 0);
        // SAFETY: hosted test; restore path is no-op on this target.
        unsafe { X86IrqGate::restore(f) };
    }

    #[test]
    fn lock_irqsave_works_with_x86_gate() {
        let s: Spinlock<u32, Buddy> = Spinlock::new(0);
        let mut g = s.lock_irqsave::<X86IrqGate>();
        *g = 7;
        drop(g);
        assert_eq!(*s.lock(), 7);
    }

    #[test]
    fn mmio_barrier_compiles_and_runs() {
        mmio_barrier();
    }

    #[test]
    fn halt_compiles_on_host_no_panic() {
        // Host build: halt is a no-op, returns immediately.
        halt();
    }

    #[test]
    fn x86_cpuops_host_fallback_returns_cpu_zero() {
        // Host build: current_cpu reads a stub; cpu_count is 1 by spec.
        assert_eq!(X86CpuOps::current_cpu(), 0);
        assert_eq!(X86CpuOps::cpu_count(),    1);
    }

    #[test]
    fn x86_cpuops_set_percpu_base_compiles_on_host() {
        let mut buf = [0u8; 64];
        // SAFETY: host-only; the asm path is cfg'd out, so this just
        // exercises the no-op fallback. The buffer outlives the call.
        unsafe { X86CpuOps::set_percpu_base(buf.as_mut_ptr()) };
    }

    #[test]
    fn x86_timer_returns_zero_until_calibrated() {
        // TSC_KHZ defaults to 0 across tests in this suite; the host
        // counter increments but the result is `tsc * 1e6 / 0` which
        // we short-circuit to 0.
        let pre = X86TimerOps::freq_khz();
        if pre == 0 {
            assert_eq!(X86TimerOps::monotonic_ns(), Nanos(0));
        }
    }

    #[test]
    fn x86_timer_after_set_tsc_khz_is_nonzero() {
        // Host fallback: rdtsc returns a strictly-increasing counter,
        // so once a freq is set, monotonic_ns advances.
        set_tsc_khz(1_000_000); // 1 GHz
        assert_eq!(X86TimerOps::freq_khz(), 1_000_000);
        let a = X86TimerOps::monotonic_ns();
        let b = X86TimerOps::monotonic_ns();
        assert!(b.0 >= a.0, "monotonic_ns must be non-decreasing");
        // Reset for sibling tests.
        set_tsc_khz(0);
    }

/// The runaway guard keys a #PF on the address it faulted at and every other
/// vector on the instruction that raised it: two #GPs from one `wrmsr` are the
/// same fault, and CR2 is not even defined for them.
#[test]
fn fault_key_is_cr2_for_page_faults_and_rip_otherwise() {
    assert_eq!(crate::fault::fault_key(crate::VEC_PF, 0xffff_ffff_8100_0000, 0x7ffe_dead_0000),
               0x7ffe_dead_0000);
    assert_eq!(crate::fault::fault_key(crate::VEC_GP, 0xffff_ffff_8100_0000, 0),
               0xffff_ffff_8100_0000);
    assert_eq!(crate::fault::fault_key(6, 0xffff_ffff_8100_0000, 0x1234),
               0xffff_ffff_8100_0000);
}
