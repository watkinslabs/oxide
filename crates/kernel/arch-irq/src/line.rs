//! Line-numbered IRQ dispatch tables for Linux-shaped handlers.

#[cfg(target_arch = "aarch64")]
use core::sync::atomic::AtomicU32;
use core::sync::atomic::{AtomicPtr, Ordering};
use hal::TimerOps;
use sync::{Devices, Spinlock};

use crate::spurious::{IrqReport, SpuriousState};

mod wake;
use wake::{Dispatch as WakeDispatch, WakeState};
pub use wake::{irq_set_irq_wake, resume_device_irqs, suspend_device_irqs};

pub type LineHandler = fn(u32) -> IrqReport;

struct LineDescriptor {
    handler: AtomicPtr<()>,
    spurious: Spinlock<SpuriousState, Devices>,
    wake: WakeState,
}

impl LineDescriptor {
    const fn new() -> Self {
        Self { handler: AtomicPtr::new(core::ptr::null_mut()),
            spurious: Spinlock::new(SpuriousState::new()), wake: WakeState::new() }
    }

    fn install(&self, handler: LineHandler) {
        self.spurious.lock().reset();
        self.wake.reset();
        self.handler.store(handler as *mut (), Ordering::Release);
    }

    fn free(&self) {
        self.handler.store(core::ptr::null_mut(), Ordering::Release);
        self.spurious.lock().reset();
        self.wake.reset();
    }

    fn installed(&self) -> bool { !self.handler.load(Ordering::Acquire).is_null() }
}

#[cfg(target_arch = "aarch64")]
struct ArmLineDescriptor { intid: AtomicU32, line: LineDescriptor }

#[cfg(target_arch = "aarch64")]
impl ArmLineDescriptor {
    const fn new() -> Self { Self { intid: AtomicU32::new(0), line: LineDescriptor::new() } }
}

/// True when the generic detector has shut down `line`. # C: O(N_arm_slots)
pub fn irq_line_disabled(line: u32) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        if line < hal_x86_64::VEC_MSI_POOL_FIRST as u32
            || line > hal_x86_64::VEC_MSI_POOL_LAST as u32
        {
            return false;
        }
        let idx = (line as u8 - hal_x86_64::VEC_MSI_POOL_FIRST) as usize;
        return X86_LINES[idx].spurious.lock().disabled();
    }
    #[cfg(target_arch = "aarch64")]
    {
        return arm_line_disabled(line, &ARM_FIXED_LINES)
            || arm_line_disabled(line, &ARM_MSI_LINES);
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { let _ = line; false }
}

/// Install a Linux-shaped handler for an x86 MSI vector.
/// # C: O(1) atomic store
#[cfg(target_arch = "x86_64")]
pub fn register_irq_line_handler(vector: u32, handler: LineHandler) -> Result<(), ()> {
    if vector < hal_x86_64::VEC_MSI_POOL_FIRST as u32
        || vector > hal_x86_64::VEC_MSI_POOL_LAST as u32
    {
        return Err(());
    }
    let idx = (vector as u8 - hal_x86_64::VEC_MSI_POOL_FIRST) as usize;
    X86_LINES[idx].install(handler);
    Ok(())
}

/// Remove a Linux-shaped x86 MSI-vector handler.
/// # C: O(1)
#[cfg(target_arch = "x86_64")]
pub fn free_irq_line_handler(vector: u32) -> Result<(), ()> {
    if vector < hal_x86_64::VEC_MSI_POOL_FIRST as u32
        || vector > hal_x86_64::VEC_MSI_POOL_LAST as u32
    {
        return Err(());
    }
    let idx = (vector as u8 - hal_x86_64::VEC_MSI_POOL_FIRST) as usize;
    X86_LINES[idx].free();
    Ok(())
}

/// Invoke a Linux-shaped x86 MSI-vector handler.
/// # C: O(1)
#[cfg(target_arch = "x86_64")]
pub fn invoke_x86_line_handler(vector: u8) -> bool {
    if vector < hal_x86_64::VEC_MSI_POOL_FIRST
        || vector > hal_x86_64::VEC_MSI_POOL_LAST
    {
        return false;
    }
    let idx = (vector - hal_x86_64::VEC_MSI_POOL_FIRST) as usize;
    invoke_line(&X86_LINES[idx], vector as u32)
}

#[cfg(target_arch = "x86_64")]
static X86_LINES: [LineDescriptor; hal_x86_64::VEC_MSI_POOL_LEN] =
    [const { LineDescriptor::new() }; hal_x86_64::VEC_MSI_POOL_LEN];

#[cfg(target_arch = "aarch64")]
const ARM_FIXED_LINE_SLOTS: usize = 16;
#[cfg(target_arch = "aarch64")]
const ARM_MSI_LINE_SLOTS: usize = 32;

/// Install a Linux-shaped fixed-INTID handler.
/// # C: O(N) atomic scan
#[cfg(target_arch = "aarch64")]
pub fn request_arm_irq_line_handler(intid: u32, handler: LineHandler) -> Result<(), ()> {
    request_arm_line_handler(intid, handler, &ARM_FIXED_LINES)
}

/// Remove a Linux-shaped fixed-INTID handler.
/// # C: O(N) atomic scan
#[cfg(target_arch = "aarch64")]
pub fn free_arm_irq_line_handler(intid: u32) -> Result<(), ()> {
    free_arm_line_handler(intid, &ARM_FIXED_LINES)
}

/// Dispatch path for Linux-shaped fixed ARM INTID handlers.
/// # C: O(N) atomic scan
#[cfg(target_arch = "aarch64")]
pub fn invoke_arm_irq_line_handler(intid: u32) -> bool {
    invoke_arm_line_handler(intid, &ARM_FIXED_LINES)
}

/// Install a Linux-shaped handler for an ARM MSI INTID.
/// # C: O(N) atomic scan
#[cfg(target_arch = "aarch64")]
pub fn register_msi_line_handler(spi: u32, handler: LineHandler) -> Result<(), ()> {
    request_arm_line_handler(spi, handler, &ARM_MSI_LINES)
}

/// Remove a Linux-shaped handler for an ARM MSI INTID.
/// # C: O(N) atomic scan
#[cfg(target_arch = "aarch64")]
pub fn free_msi_line_handler(spi: u32) -> Result<(), ()> {
    free_arm_line_handler(spi, &ARM_MSI_LINES)
}

/// Dispatch path for Linux-shaped ARM MSI handlers.
/// # C: O(N) atomic scan
#[cfg(target_arch = "aarch64")]
pub fn invoke_arm_spi_line_handler(intid: u32) -> bool {
    invoke_arm_line_handler(intid, &ARM_MSI_LINES)
}

#[cfg(target_arch = "aarch64")]
static ARM_FIXED_LINES: [ArmLineDescriptor; ARM_FIXED_LINE_SLOTS] =
    [const { ArmLineDescriptor::new() }; ARM_FIXED_LINE_SLOTS];
#[cfg(target_arch = "aarch64")]
static ARM_MSI_LINES: [ArmLineDescriptor; ARM_MSI_LINE_SLOTS] =
    [const { ArmLineDescriptor::new() }; ARM_MSI_LINE_SLOTS];

#[cfg(target_arch = "aarch64")]
fn request_arm_line_handler<const N: usize>(
    intid: u32,
    handler: LineHandler,
    lines: &[ArmLineDescriptor; N],
) -> Result<(), ()> {
    if intid == 0 { return Err(()); }
    for entry in lines {
        if entry.intid.load(Ordering::Acquire) == intid {
            entry.line.install(handler);
            return Ok(());
        }
    }
    for entry in lines {
        if entry.intid
            .compare_exchange(0, intid, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            entry.line.install(handler);
            return Ok(());
        }
    }
    Err(())
}

#[cfg(target_arch = "aarch64")]
fn free_arm_line_handler<const N: usize>(
    intid: u32,
    lines: &[ArmLineDescriptor; N],
) -> Result<(), ()> {
    for entry in lines {
        if entry.intid.load(Ordering::Acquire) == intid {
            entry.line.free();
            entry.intid.store(0, Ordering::Release);
            return Ok(());
        }
    }
    Err(())
}

#[cfg(target_arch = "aarch64")]
fn invoke_arm_line_handler<const N: usize>(
    intid: u32,
    lines: &[ArmLineDescriptor; N],
) -> bool {
    for entry in lines {
        if entry.intid.load(Ordering::Acquire) == intid {
            return invoke_line(&entry.line, intid);
        }
    }
    false
}

#[cfg(target_arch = "aarch64")]
fn arm_line_disabled<const N: usize>(
    intid: u32,
    lines: &[ArmLineDescriptor; N],
) -> bool {
    for entry in lines {
        if entry.intid.load(Ordering::Acquire) == intid {
            return entry.line.spurious.lock().disabled();
        }
    }
    false
}

fn invoke_line(descriptor: &LineDescriptor, irq: u32) -> bool {
    let raw = descriptor.handler.load(Ordering::Acquire);
    if raw.is_null() { return false; }
    if descriptor.spurious.lock().disabled() { return false; }
    match descriptor.wake.dispatch() {
        WakeDispatch::Wake => {
            disable_line(irq);
            power::pm_system_irq_wakeup(irq);
            return true;
        }
        WakeDispatch::Suspended => return true,
        WakeDispatch::Run => {}
    }
    // SAFETY: raw was installed by a line-handler registration path with LineHandler ABI.
    let f: LineHandler = unsafe { core::mem::transmute(raw) };
    let report = f(irq);
    let disable = descriptor.spurious.lock().note(now_ns(), report);
    if disable { disable_line(irq); }
    true
}

#[cfg(target_arch = "x86_64")]
fn now_ns() -> u64 { hal_x86_64::X86TimerOps::monotonic_ns().0 }

#[cfg(target_arch = "aarch64")]
fn now_ns() -> u64 { hal_aarch64::ArmTimerOps::monotonic_ns().0 }

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn disable_line(vector: u32) {
    if let Ok(vector) = u8::try_from(vector) {
        // SAFETY: vector routing was published only after the I/O APIC mapping became live.
        unsafe { hal_x86_64::ioapic::mask_vector(vector); }
    }
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn disable_line(intid: u32) {
    // SAFETY: the registered line descriptor owns this INTID.
    unsafe { crate::gic::disable_intid(intid); }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn disable_line(_line: u32) {}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn enable_line(vector: u32) {
    if let Ok(vector) = u8::try_from(vector) {
        // SAFETY: the registered descriptor still owns this routed vector.
        unsafe { hal_x86_64::ioapic::unmask_vector(vector); }
    }
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn enable_line(intid: u32) {
    // SAFETY: the registered line descriptor still owns this INTID.
    unsafe { crate::gic::enable_intid(intid); }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn enable_line(_line: u32) {}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};
    use crate::{IrqReport, IrqRet};

    static HITS: AtomicU32 = AtomicU32::new(0);

    fn not_mine(_irq: u32) -> IrqReport {
        HITS.fetch_add(1, Ordering::Relaxed);
        IrqReport::hard(IrqRet::NotMine)
    }

    #[test]
    fn disabled_descriptor_stops_invoking_its_handler() {
        HITS.store(0, Ordering::Relaxed);
        let descriptor = LineDescriptor::new();
        descriptor.install(not_mine);
        for _ in 0..100_000 {
            assert!(invoke_line(&descriptor, 0x40));
        }
        assert!(descriptor.spurious.lock().disabled());
        assert!(!invoke_line(&descriptor, 0x40));
        assert_eq!(HITS.load(Ordering::Relaxed), 100_000);
    }

    #[test]
    fn an_armed_delivery_posts_pm_wakeup_before_handler_replay() {
        power::suspend::wakeup::pm_wakeup_clear(0);
        HITS.store(0, Ordering::Relaxed);
        let descriptor = LineDescriptor::new();
        descriptor.install(not_mine);
        assert!(descriptor.wake.set(true));
        assert!(!descriptor.wake.suspend());
        assert!(invoke_line(&descriptor, 0x40));
        assert_eq!(HITS.load(Ordering::Relaxed), 0);
        assert!(power::pm_wakeup_pending());
        assert_eq!(descriptor.wake.resume(), (true, true));
        assert!(invoke_line(&descriptor, 0x40));
        assert_eq!(HITS.load(Ordering::Relaxed), 1);
        power::suspend::wakeup::pm_wakeup_clear(0);
    }
}
