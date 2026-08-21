//! Migration-safe local preemption-count access.

#[cfg(target_os = "oxide-kernel")]
use core::sync::atomic::{AtomicU32, Ordering};
#[cfg(target_os = "oxide-kernel")]
use cpu::MAX_CPUS;
#[cfg(target_os = "oxide-kernel")]
use sync::IrqGate;

#[cfg(target_os = "oxide-kernel")]
#[repr(C, align(64))]
struct Pcpu<T>(T);

#[cfg(target_os = "oxide-kernel")]
const PC_ZERO: Pcpu<AtomicU32> = Pcpu(AtomicU32::new(0));

/// The one kernel-target preemption-count owner.
#[cfg(target_os = "oxide-kernel")]
static PREEMPT_COUNT: [Pcpu<AtomicU32>; MAX_CPUS] = [PC_ZERO; MAX_CPUS];

#[cfg(not(target_os = "oxide-kernel"))]
std::thread_local! {
    static HOSTED_PREEMPT_COUNT: core::cell::Cell<u32> = const { core::cell::Cell::new(0) };
}

/// Current CPU index. Kernel callers select a count slot only after masking
/// local IRQs, so an IRQ-return reschedule cannot migrate the task between
/// selection and the operation. # C: O(1)
#[inline]
pub(crate) fn this_cpu() -> usize {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; (hal_x86_64::X86CpuOps::current_cpu() as usize).min(MAX_CPUS - 1) }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; (hal_aarch64::ArmCpuOps::current_cpu() as usize).min(MAX_CPUS - 1) }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn hosted<R>(f: impl FnOnce(&core::cell::Cell<u32>) -> R) -> R {
    HOSTED_PREEMPT_COUNT.with(f)
}

/// Run one local-slot operation while CPU identity is IRQ-pinned. The arch
/// gates are raw IF/DAIF register operations and never touch preempt_count, so
/// this lowest-level owner cannot recurse into itself. # C: O(1)
#[cfg(target_os = "oxide-kernel")]
#[inline]
fn with_local<R>(f: impl FnOnce(&AtomicU32) -> R) -> R {
    #[cfg(target_arch = "x86_64")]
    type Gate = hal_x86_64::X86IrqGate;
    #[cfg(target_arch = "aarch64")]
    type Gate = hal_aarch64::ArmIrqGate;
    // SAFETY: restore consumes this exact token after the slot selection and
    // atomic operation; neither closure nor atomic access can unwind.
    let flags = unsafe { Gate::save_disable() };
    let result = f(&PREEMPT_COUNT[this_cpu()].0);
    // SAFETY: flags came from the matching gate call in this frame.
    unsafe { Gate::restore(flags); }
    result
}

pub(super) fn preempt_count_load() -> u32 {
    #[cfg(not(target_os = "oxide-kernel"))]
    { return hosted(core::cell::Cell::get); }
    #[cfg(target_os = "oxide-kernel")]
    { with_local(|slot| slot.load(Ordering::Acquire)) }
}

pub(super) fn preempt_count_add_local(n: u32) {
    #[cfg(not(target_os = "oxide-kernel"))]
    { hosted(|count| count.set(count.get().wrapping_add(n))); }
    #[cfg(target_os = "oxide-kernel")]
    { with_local(|slot| { slot.fetch_add(n, Ordering::AcqRel); }); }
}

// Checked before the sub: afterwards wrapping is indistinguishable from nesting.
#[track_caller]
pub(super) fn preempt_count_sub_local(n: u32) -> u32 {
    #[cfg(feature = "debug-preempt")]
    super::debug::check_preempt_sub(preempt_count_load(), n);
    #[cfg(not(target_os = "oxide-kernel"))]
    { return hosted(|count| { let prev = count.get(); count.set(prev.wrapping_sub(n)); prev }); }
    #[cfg(target_os = "oxide-kernel")]
    { with_local(|slot| slot.fetch_sub(n, Ordering::AcqRel)) }
}

/// Live count of an arbitrary CPU; diagnostics intentionally do not claim a
/// local-CPU snapshot. Out-of-range yields zero. # C: O(1)
pub fn preempt_count_on(cpu: usize) -> u32 {
    #[cfg(not(target_os = "oxide-kernel"))]
    { let _ = cpu; return 0; }
    #[cfg(target_os = "oxide-kernel")]
    { PREEMPT_COUNT.get(cpu).map_or(0, |s| s.0.load(Ordering::Acquire)) }
}

/// Replace this CPU's count at the scheduler/softirq recovery boundary.
/// # C: O(1)
pub(crate) fn preempt_count_set(value: u32) {
    #[cfg(not(target_os = "oxide-kernel"))]
    { hosted(|count| count.set(value)); }
    #[cfg(target_os = "oxide-kernel")]
    { with_local(|slot| slot.store(value, Ordering::Release)); }
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    #[test]
    fn split_selection_reproduces_cross_cpu_credit() {
        let slots = [Cell::new(0u32), Cell::new(0u32)];
        let cpu = Cell::new(0usize);
        let sampled = cpu.get();
        cpu.set(1); // IRQ-return migration in the old select-then-RMW window.
        slots[sampled].set(slots[sampled].get() + 1);
        slots[cpu.get()].set(slots[cpu.get()].get().wrapping_sub(1));
        assert_eq!((slots[0].get(), slots[1].get()), (1, u32::MAX));
    }

    #[test]
    fn irq_pin_keeps_selection_and_operation_on_one_cpu() {
        let slots = [Cell::new(0u32), Cell::new(0u32)];
        let cpu = Cell::new(0usize);
        let irq_masked = Cell::new(false);
        irq_masked.set(true);
        let selected = cpu.get();
        if !irq_masked.get() { cpu.set(1); }
        slots[selected].set(slots[selected].get() + 1);
        irq_masked.set(false);
        assert_eq!((slots[0].get(), slots[1].get()), (1, 0));
    }
}
