use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use power::hibernate::log::{self, IrqKind, IrqPhase};
use sync::IrqGate;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) enum Dispatch { Run, Wake, Suspended }

pub(super) struct WakeState {
    depth: AtomicU32,
    armed: AtomicBool,
    suspended: AtomicBool,
    pending: AtomicBool,
}

impl WakeState {
    pub(super) const fn new() -> Self {
        Self { depth: AtomicU32::new(0), armed: AtomicBool::new(false),
            suspended: AtomicBool::new(false), pending: AtomicBool::new(false) }
    }

    pub(super) fn reset(&self) {
        self.depth.store(0, Ordering::Release);
        self.armed.store(false, Ordering::Release);
        self.suspended.store(false, Ordering::Release);
        self.pending.store(false, Ordering::Release);
    }

    pub(super) fn set(&self, enabled: bool) -> bool {
        if enabled {
            self.depth.fetch_update(Ordering::AcqRel, Ordering::Acquire,
                |depth| depth.checked_add(1)).is_ok()
        } else {
            self.depth.fetch_update(Ordering::AcqRel, Ordering::Acquire,
                |depth| if depth == 0 { None } else { Some(depth - 1) }).is_ok()
        }
    }

    /// Enter the IRQ-core suspended state. Returns true when hardware should
    /// be masked; wake-enabled lines remain live and become armed instead.
    pub(super) fn suspend(&self) -> bool {
        self.pending.store(false, Ordering::Release);
        self.suspended.store(false, Ordering::Release);
        if self.depth.load(Ordering::Acquire) != 0 {
            self.armed.store(true, Ordering::Release);
            false
        } else {
            self.armed.store(false, Ordering::Release);
            self.suspended.store(true, Ordering::Release);
            true
        }
    }

    pub(super) fn dispatch(&self) -> Dispatch {
        if self.armed.swap(false, Ordering::AcqRel) {
            self.pending.store(true, Ordering::Release);
            self.suspended.store(true, Ordering::Release);
            return Dispatch::Wake;
        }
        if self.suspended.load(Ordering::Acquire) {
            self.pending.store(true, Ordering::Release);
            return Dispatch::Suspended;
        }
        Dispatch::Run
    }

    /// Leave the suspended state; return `(was_suspended, needs_replay)`.
    pub(super) fn resume(&self) -> (bool, bool) {
        self.armed.store(false, Ordering::Release);
        let was_suspended = self.suspended.swap(false, Ordering::AcqRel);
        let pending = self.pending.swap(false, Ordering::AcqRel);
        (was_suspended, was_suspended && pending)
    }
}

/// Adjust one installed IRQ descriptor's balanced system-wakeup depth.
/// # C: O(1) x86, O(N) aarch64
pub fn irq_set_irq_wake(line: u32, enabled: bool) -> Result<(), ()> {
    if let Some(result) = crate::msi_suspend::set_wake(line, enabled) {
        return result.then_some(()).ok_or(());
    }
    #[cfg(target_arch = "x86_64")]
    {
        if line < hal_x86_64::VEC_MSI_POOL_FIRST as u32
            || line > hal_x86_64::VEC_MSI_POOL_LAST as u32 { return Err(()); }
        let index = (line as u8 - hal_x86_64::VEC_MSI_POOL_FIRST) as usize;
        let descriptor = &super::X86_LINES[index];
        if !descriptor.installed() { return Err(()); }
        return descriptor.wake.set(enabled).then_some(()).ok_or(());
    }
    #[cfg(target_arch = "aarch64")]
    {
        if let Some(result) = set_arm_irq_wake(line, enabled, &super::ARM_FIXED_LINES) {
            return result;
        }
        set_arm_irq_wake(line, enabled, &super::ARM_MSI_LINES)
            .unwrap_or(Err(()))
    }
}

#[cfg(target_arch = "aarch64")]
fn set_arm_irq_wake<const N: usize>(line: u32, enabled: bool,
    lines: &[super::ArmLineDescriptor; N]) -> Option<Result<(), ()>> {
    for descriptor in lines {
        if descriptor.intid.load(Ordering::Acquire) == line {
            if !descriptor.line.installed() { return Some(Err(())); }
            return Some(descriptor.line.wake.set(enabled).then_some(()).ok_or(()));
        }
    }
    None
}

/// Arm wake-enabled descriptors and mask every other installed device IRQ.
/// # C: O(N_IRQ descriptors)
pub fn suspend_device_irqs() {
    #[cfg(target_arch = "x86_64")]
    for (index, descriptor) in super::X86_LINES.iter().enumerate() {
        if !descriptor.installed() { continue; }
        let line = u32::from(hal_x86_64::VEC_MSI_POOL_FIRST) + index as u32;
        suspend_descriptor::<hal_x86_64::X86IrqGate>(descriptor, line,
            || super::disable_line(line));
    }
    #[cfg(target_arch = "aarch64")]
    suspend_arm_lines(&super::ARM_FIXED_LINES);
    #[cfg(target_arch = "aarch64")]
    suspend_arm_lines(&super::ARM_MSI_LINES);
    crate::msi_suspend::suspend_all();
}

#[cfg(target_arch = "aarch64")]
fn suspend_arm_lines<const N: usize>(lines: &[super::ArmLineDescriptor; N]) {
    for descriptor in lines {
        let line = descriptor.intid.load(Ordering::Acquire);
        if line == 0 || !descriptor.line.installed() { continue; }
        suspend_descriptor::<hal_aarch64::ArmIrqGate>(&descriptor.line, line,
            || super::disable_line(line));
    }
}

fn suspend_descriptor<I: IrqGate>(descriptor: &super::LineDescriptor, irq: u32,
    mask: impl FnOnce())
{
    let spurious = descriptor.spurious.lock_irqsave::<I>();
    if spurious.disabled() { return; }
    log::noirq_irq(IrqKind::Line, irq, IrqPhase::Descriptor, descriptor.in_flight.active());
    if descriptor.wake.suspend() {
        log::noirq_irq(IrqKind::Line, irq, IrqPhase::MaskBegin, descriptor.in_flight.active());
        mask();
        log::noirq_irq(IrqKind::Line, irq, IrqPhase::MaskEnd, descriptor.in_flight.active());
        log::noirq_irq(IrqKind::Line, irq, IrqPhase::SyncBegin, descriptor.in_flight.active());
        descriptor.in_flight.synchronize();
        log::noirq_irq(IrqKind::Line, irq, IrqPhase::SyncEnd, descriptor.in_flight.active());
    }
}

/// Replay a delivery consumed as a wake event, then re-enable suspended IRQs.
/// # C: O(N_IRQ descriptors + pending handlers)
pub fn resume_device_irqs() {
    crate::msi_suspend::resume_all();
    #[cfg(target_arch = "x86_64")]
    for (index, descriptor) in super::X86_LINES.iter().enumerate() {
        let (suspended, pending) = descriptor.wake.resume();
        if !suspended { continue; }
        let line = u32::from(hal_x86_64::VEC_MSI_POOL_FIRST) + index as u32;
        if pending { let _ = super::invoke_line(descriptor, line); }
        if !descriptor.spurious.lock().disabled() { super::enable_line(line); }
    }
    #[cfg(target_arch = "aarch64")]
    resume_arm_lines(&super::ARM_FIXED_LINES);
    #[cfg(target_arch = "aarch64")]
    resume_arm_lines(&super::ARM_MSI_LINES);
}

#[cfg(target_arch = "aarch64")]
fn resume_arm_lines<const N: usize>(lines: &[super::ArmLineDescriptor; N]) {
    for descriptor in lines {
        let (suspended, pending) = descriptor.line.wake.resume();
        if !suspended { continue; }
        let line = descriptor.intid.load(Ordering::Acquire);
        if pending { let _ = super::invoke_line(&descriptor.line, line); }
        if !descriptor.line.spurious.lock().disabled() { super::enable_line(line); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicU32;

    static IRQ_STATE: AtomicU32 = AtomicU32::new(0);

    struct TestIrqGate;
    impl IrqGate for TestIrqGate {
        unsafe fn save_enable() -> u64 { 0 }
        unsafe fn save_disable() -> u64 {
            assert_eq!(IRQ_STATE.swap(1, Ordering::SeqCst), 0);
            7
        }
        unsafe fn restore(flags: u64) {
            assert_eq!(flags, 7);
            assert_eq!(IRQ_STATE.swap(2, Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn balanced_depth_arms_only_on_the_outer_edges() {
        let state = WakeState::new();
        assert!(state.set(true));
        assert!(state.set(true));
        assert!(!state.suspend());
        assert_eq!(state.dispatch(), Dispatch::Wake);
        assert_eq!(state.dispatch(), Dispatch::Suspended);
        assert_eq!(state.resume(), (true, true));
        assert!(state.set(false));
        assert!(!state.suspend(), "one remaining owner must keep the IRQ armed");
        assert!(state.set(false));
        assert!(state.suspend(), "zero owners must suspend and mask the IRQ");
        assert!(!state.set(false), "an unbalanced disable must fail");
    }

    #[test]
    fn ordinary_lines_are_suspended_without_becoming_wake_events() {
        let state = WakeState::new();
        assert!(state.suspend());
        assert_eq!(state.dispatch(), Dispatch::Suspended);
        assert_eq!(state.resume(), (true, true));
        assert_eq!(state.dispatch(), Dispatch::Run);
    }

    #[test]
    fn descriptor_irq_gate_spans_suspend_decision_and_hardware_mask() {
        IRQ_STATE.store(0, Ordering::SeqCst);
        let descriptor = super::super::LineDescriptor::new();
        suspend_descriptor::<TestIrqGate>(&descriptor, 7, || {
            assert_eq!(IRQ_STATE.load(Ordering::SeqCst), 1,
                "hardware mask must run while the descriptor IRQ gate is held");
        });
        assert_eq!(IRQ_STATE.load(Ordering::SeqCst), 2);
    }
}
