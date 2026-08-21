//! One lifecycle owner for PCI/platform MSI handlers across system sleep.

#[cfg(target_arch = "aarch64")]
use core::sync::atomic::Ordering;
use sync::{Devices, IrqGate, Spinlock};
use power::hibernate::log::{self, IrqKind, IrqPhase};

use crate::irq_sync::{InFlight, InFlightGuard};

pub type SourceMask = fn(u64, u64, bool);

struct State {
    installed: bool,
    suspended: bool,
    armed: bool,
    pending: bool,
    wake_depth: u32,
    source_mask: Option<SourceMask>,
    arg0: u64,
    arg1: u64,
}

impl State {
    const fn new() -> Self {
        Self { installed: false, suspended: false, armed: false, pending: false,
            wake_depth: 0, source_mask: None, arg0: 0, arg1: 0 }
    }
}

struct Descriptor { state: Spinlock<State, Devices>, in_flight: InFlight }

impl Descriptor {
    const fn new() -> Self {
        Self { state: Spinlock::new(State::new()), in_flight: InFlight::new() }
    }
}

#[cfg(target_arch = "x86_64")]
static DESCRIPTORS: [Descriptor; hal_x86_64::VEC_MSI_POOL_LEN] =
    [const { Descriptor::new() }; hal_x86_64::VEC_MSI_POOL_LEN];
#[cfg(target_arch = "aarch64")]
static DESCRIPTORS: [Descriptor; crate::ARM_MSI_SLOTS] =
    [const { Descriptor::new() }; crate::ARM_MSI_SLOTS];

fn descriptor(irq: u32) -> Option<&'static Descriptor> {
    #[cfg(target_arch = "x86_64")]
    {
        let vector = u8::try_from(irq).ok()?;
        if vector < hal_x86_64::VEC_MSI_POOL_FIRST || vector > hal_x86_64::VEC_MSI_POOL_LAST {
            return None;
        }
        DESCRIPTORS.get((vector - hal_x86_64::VEC_MSI_POOL_FIRST) as usize)
    }
    #[cfg(target_arch = "aarch64")]
    {
        for (index, spi) in crate::ARM_MSI_SPIS.iter().enumerate() {
            if spi.load(Ordering::Acquire) == irq { return DESCRIPTORS.get(index); }
        }
        None
    }
}

pub(crate) fn install(irq: u32) -> bool {
    let Some(descriptor) = descriptor(irq) else { return false; };
    let mut state = descriptor.state.lock();
    state.installed = true;
    state.suspended = false;
    state.armed = false;
    state.pending = false;
    true
}

pub(crate) fn uninstall(irq: u32) {
    let Some(descriptor) = descriptor(irq) else { return; };
    descriptor.in_flight.synchronize();
    *descriptor.state.lock() = State::new();
}

/// Bind the architecture IRQ descriptor to its device-level MSI/MSI-X mask.
/// # C: O(1)
pub fn set_source_mask(irq: u32, mask: SourceMask, arg0: u64, arg1: u64) -> bool {
    let Some(descriptor) = descriptor(irq) else { return false; };
    let mut state = descriptor.state.lock();
    if !state.installed { return false; }
    state.source_mask = Some(mask);
    state.arg0 = arg0;
    state.arg1 = arg1;
    true
}

pub(crate) fn set_wake(irq: u32, enabled: bool) -> Option<bool> {
    let descriptor = descriptor(irq)?;
    let mut state = descriptor.state.lock();
    if !state.installed { return Some(false); }
    if enabled {
        let Some(depth) = state.wake_depth.checked_add(1) else { return Some(false); };
        state.wake_depth = depth;
    } else if state.wake_depth == 0 {
        return Some(false);
    } else {
        state.wake_depth -= 1;
    }
    Some(true)
}

pub(crate) enum Dispatch<'a> { Run(InFlightGuard<'a>), Wake, Suspended, Absent }

pub(crate) fn begin(irq: u32) -> Dispatch<'static> {
    let Some(descriptor) = descriptor(irq) else { return Dispatch::Absent; };
    let mut state = descriptor.state.lock();
    if !state.installed { return Dispatch::Absent; }
    if state.armed {
        state.armed = false;
        state.suspended = true;
        state.pending = true;
        if let Some(mask) = state.source_mask { mask(state.arg0, state.arg1, true); }
        return Dispatch::Wake;
    }
    if state.suspended {
        state.pending = true;
        return Dispatch::Suspended;
    }
    Dispatch::Run(descriptor.in_flight.enter())
}

fn suspend_descriptor<I: IrqGate>(descriptor: &Descriptor, _irq: u32) {
    let source = {
        let mut state = descriptor.state.lock_irqsave::<I>();
        if !state.installed { return; }
        log::noirq_irq(IrqKind::Msi, _irq, IrqPhase::Descriptor, descriptor.in_flight.active());
        state.pending = false;
        if state.wake_depth != 0 {
            state.armed = true;
            state.suspended = false;
            return;
        }
        state.armed = false;
        state.suspended = true;
        state.source_mask.map(|mask| (mask, state.arg0, state.arg1))
    };
    log::noirq_irq(IrqKind::Msi, _irq, IrqPhase::MaskBegin, descriptor.in_flight.active());
    if let Some((mask, arg0, arg1)) = source { mask(arg0, arg1, true); }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    let _ = crate::msi::set_arm_irq_enabled(_irq, false);
    log::noirq_irq(IrqKind::Msi, _irq, IrqPhase::MaskEnd, descriptor.in_flight.active());
    log::noirq_irq(IrqKind::Msi, _irq, IrqPhase::SyncBegin, descriptor.in_flight.active());
    descriptor.in_flight.synchronize();
    log::noirq_irq(IrqKind::Msi, _irq, IrqPhase::SyncEnd, descriptor.in_flight.active());
}

pub(crate) fn suspend_all() {
    #[cfg(target_arch = "x86_64")]
    for (index, descriptor) in DESCRIPTORS.iter().enumerate() {
        suspend_descriptor::<hal_x86_64::X86IrqGate>(descriptor,
            u32::from(hal_x86_64::VEC_MSI_POOL_FIRST) + index as u32);
    }
    #[cfg(target_arch = "aarch64")]
    for (index, descriptor) in DESCRIPTORS.iter().enumerate() {
        let irq = crate::ARM_MSI_SPIS[index].load(Ordering::Acquire);
        if irq != 0 { suspend_descriptor::<hal_aarch64::ArmIrqGate>(descriptor, irq); }
    }
}

fn resume_descriptor<I: IrqGate>(descriptor: &Descriptor, _irq: u32) -> bool {
    let source = {
        let mut state = descriptor.state.lock_irqsave::<I>();
        if !state.installed { return false; }
        state.armed = false;
        if !state.suspended {
            let replay = state.pending;
            state.pending = false;
            return replay;
        }
        state.source_mask.map(|mask| (mask, state.arg0, state.arg1))
    };
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    let _ = crate::msi::set_arm_irq_enabled(_irq, true);
    if let Some((mask, arg0, arg1)) = source { mask(arg0, arg1, false); }
    let mut state = descriptor.state.lock_irqsave::<I>();
    let replay = state.pending;
    state.pending = false;
    state.suspended = false;
    replay
}

pub(crate) fn resume_all() {
    #[cfg(target_arch = "x86_64")]
    for (index, descriptor) in DESCRIPTORS.iter().enumerate() {
        let irq = u32::from(hal_x86_64::VEC_MSI_POOL_FIRST) + index as u32;
        if resume_descriptor::<hal_x86_64::X86IrqGate>(descriptor, irq) {
            crate::msi::invoke_x86_owned(irq);
        }
    }
    #[cfg(target_arch = "aarch64")]
    for (index, descriptor) in DESCRIPTORS.iter().enumerate() {
        let irq = crate::ARM_MSI_SPIS[index].load(Ordering::Acquire);
        if irq != 0 && resume_descriptor::<hal_aarch64::ArmIrqGate>(descriptor, irq) {
            let _ = crate::msi_context::invoke_arm_spi_handler(irq);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};

    static MASKS: AtomicU32 = AtomicU32::new(0);
    static REPLAYS: AtomicU32 = AtomicU32::new(0);
    fn mask(_: u64, _: u64, masked: bool) {
        MASKS.fetch_add(if masked { 1 } else { 10 }, Ordering::AcqRel);
    }
    fn replay(_: usize) { REPLAYS.fetch_add(1, Ordering::AcqRel); }

    #[test]
    fn suspended_msi_refuses_dispatch_and_replays_after_unmask() {
        let irq = u32::from(hal_x86_64::VEC_MSI_POOL_FIRST + 1);
        crate::msi_context::register_x86(irq as u8, replay, 0).unwrap();
        assert!(install(irq));
        assert!(set_source_mask(irq, mask, 0, 0));
        MASKS.store(0, Ordering::Release);
        REPLAYS.store(0, Ordering::Release);
        suspend_all();
        assert!(matches!(begin(irq), Dispatch::Suspended));
        resume_all();
        assert_eq!(MASKS.load(Ordering::Acquire), 11);
        assert_eq!(REPLAYS.load(Ordering::Acquire), 1);
        uninstall(irq);
        crate::msi_context::clear_x86(irq as u8);
    }

    #[test]
    fn wake_depth_is_balanced_and_wake_delivery_becomes_pending() {
        let irq = u32::from(hal_x86_64::VEC_MSI_POOL_FIRST + 2);
        assert!(install(irq));
        assert_eq!(set_wake(irq, true), Some(true));
        suspend_all();
        assert!(matches!(begin(irq), Dispatch::Wake));
        assert_eq!(set_wake(irq, false), Some(true));
        resume_all();
        uninstall(irq);
    }
}
