//! Line-numbered IRQ dispatch tables for Linux-shaped handlers.

#[cfg(target_arch = "aarch64")]
use core::sync::atomic::AtomicU32;
use core::sync::atomic::{AtomicPtr, Ordering};
use hal::TimerOps;
use sync::{Devices, Spinlock};

use crate::spurious::{IrqReport, SpuriousState};

pub type LineHandler = fn(u32) -> IrqReport;

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
        return X86_LINE_STATES[idx].lock().disabled();
    }
    #[cfg(target_arch = "aarch64")]
    {
        return arm_line_disabled(line, &ARM_FIXED_LINE_INTIDS, &ARM_FIXED_LINE_STATES)
            || arm_line_disabled(line, &ARM_MSI_LINE_INTIDS, &ARM_MSI_LINE_STATES);
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
    X86_LINE_STATES[idx].lock().reset();
    X86_LINE_HANDLERS[idx].store(handler as *mut (), Ordering::Release);
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
    X86_LINE_HANDLERS[idx].store(core::ptr::null_mut(), Ordering::Release);
    X86_LINE_STATES[idx].lock().reset();
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
    invoke_line_ptr(
        X86_LINE_HANDLERS[idx].load(Ordering::Acquire),
        vector as u32,
        &X86_LINE_STATES[idx],
    )
}

#[cfg(target_arch = "x86_64")]
static X86_LINE_HANDLERS: [AtomicPtr<()>; hal_x86_64::VEC_MSI_POOL_LEN] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; hal_x86_64::VEC_MSI_POOL_LEN];
#[cfg(target_arch = "x86_64")]
static X86_LINE_STATES: [Spinlock<SpuriousState, Devices>; hal_x86_64::VEC_MSI_POOL_LEN] =
    [const { Spinlock::new(SpuriousState::new()) }; hal_x86_64::VEC_MSI_POOL_LEN];

#[cfg(target_arch = "aarch64")]
const ARM_FIXED_LINE_SLOTS: usize = 16;
#[cfg(target_arch = "aarch64")]
const ARM_MSI_LINE_SLOTS: usize = 32;

/// Install a Linux-shaped fixed-INTID handler.
/// # C: O(N) atomic scan
#[cfg(target_arch = "aarch64")]
pub fn request_arm_irq_line_handler(intid: u32, handler: LineHandler) -> Result<(), ()> {
    request_arm_line_handler(
        intid,
        handler,
        &ARM_FIXED_LINE_INTIDS,
        &ARM_FIXED_LINE_HANDLERS,
        &ARM_FIXED_LINE_STATES,
    )
}

/// Remove a Linux-shaped fixed-INTID handler.
/// # C: O(N) atomic scan
#[cfg(target_arch = "aarch64")]
pub fn free_arm_irq_line_handler(intid: u32) -> Result<(), ()> {
    free_arm_line_handler(
        intid,
        &ARM_FIXED_LINE_INTIDS,
        &ARM_FIXED_LINE_HANDLERS,
        &ARM_FIXED_LINE_STATES,
    )
}

/// Dispatch path for Linux-shaped fixed ARM INTID handlers.
/// # C: O(N) atomic scan
#[cfg(target_arch = "aarch64")]
pub fn invoke_arm_irq_line_handler(intid: u32) -> bool {
    invoke_arm_line_handler(
        intid,
        &ARM_FIXED_LINE_INTIDS,
        &ARM_FIXED_LINE_HANDLERS,
        &ARM_FIXED_LINE_STATES,
    )
}

/// Install a Linux-shaped handler for an ARM MSI INTID.
/// # C: O(N) atomic scan
#[cfg(target_arch = "aarch64")]
pub fn register_msi_line_handler(spi: u32, handler: LineHandler) -> Result<(), ()> {
    request_arm_line_handler(
        spi,
        handler,
        &ARM_MSI_LINE_INTIDS,
        &ARM_MSI_LINE_HANDLERS,
        &ARM_MSI_LINE_STATES,
    )
}

/// Remove a Linux-shaped handler for an ARM MSI INTID.
/// # C: O(N) atomic scan
#[cfg(target_arch = "aarch64")]
pub fn free_msi_line_handler(spi: u32) -> Result<(), ()> {
    free_arm_line_handler(
        spi,
        &ARM_MSI_LINE_INTIDS,
        &ARM_MSI_LINE_HANDLERS,
        &ARM_MSI_LINE_STATES,
    )
}

/// Dispatch path for Linux-shaped ARM MSI handlers.
/// # C: O(N) atomic scan
#[cfg(target_arch = "aarch64")]
pub fn invoke_arm_spi_line_handler(intid: u32) -> bool {
    invoke_arm_line_handler(
        intid,
        &ARM_MSI_LINE_INTIDS,
        &ARM_MSI_LINE_HANDLERS,
        &ARM_MSI_LINE_STATES,
    )
}

#[cfg(target_arch = "aarch64")]
static ARM_FIXED_LINE_INTIDS: [AtomicU32; ARM_FIXED_LINE_SLOTS] =
    [const { AtomicU32::new(0) }; ARM_FIXED_LINE_SLOTS];
#[cfg(target_arch = "aarch64")]
static ARM_FIXED_LINE_HANDLERS: [AtomicPtr<()>; ARM_FIXED_LINE_SLOTS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; ARM_FIXED_LINE_SLOTS];
#[cfg(target_arch = "aarch64")]
static ARM_FIXED_LINE_STATES: [Spinlock<SpuriousState, Devices>; ARM_FIXED_LINE_SLOTS] =
    [const { Spinlock::new(SpuriousState::new()) }; ARM_FIXED_LINE_SLOTS];
#[cfg(target_arch = "aarch64")]
static ARM_MSI_LINE_INTIDS: [AtomicU32; ARM_MSI_LINE_SLOTS] =
    [const { AtomicU32::new(0) }; ARM_MSI_LINE_SLOTS];
#[cfg(target_arch = "aarch64")]
static ARM_MSI_LINE_HANDLERS: [AtomicPtr<()>; ARM_MSI_LINE_SLOTS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; ARM_MSI_LINE_SLOTS];
#[cfg(target_arch = "aarch64")]
static ARM_MSI_LINE_STATES: [Spinlock<SpuriousState, Devices>; ARM_MSI_LINE_SLOTS] =
    [const { Spinlock::new(SpuriousState::new()) }; ARM_MSI_LINE_SLOTS];

#[cfg(target_arch = "aarch64")]
fn request_arm_line_handler<const N: usize>(
    intid: u32,
    handler: LineHandler,
    intids: &[AtomicU32; N],
    handlers: &[AtomicPtr<()>; N],
    states: &[Spinlock<SpuriousState, Devices>; N],
) -> Result<(), ()> {
    if intid == 0 { return Err(()); }
    for i in 0..N {
        if intids[i].load(Ordering::Acquire) == intid {
            states[i].lock().reset();
            handlers[i].store(handler as *mut (), Ordering::Release);
            return Ok(());
        }
    }
    for i in 0..N {
        if intids[i]
            .compare_exchange(0, intid, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            states[i].lock().reset();
            handlers[i].store(handler as *mut (), Ordering::Release);
            return Ok(());
        }
    }
    Err(())
}

#[cfg(target_arch = "aarch64")]
fn free_arm_line_handler<const N: usize>(
    intid: u32,
    intids: &[AtomicU32; N],
    handlers: &[AtomicPtr<()>; N],
    states: &[Spinlock<SpuriousState, Devices>; N],
) -> Result<(), ()> {
    for i in 0..N {
        if intids[i].load(Ordering::Acquire) == intid {
            handlers[i].store(core::ptr::null_mut(), Ordering::Release);
            states[i].lock().reset();
            intids[i].store(0, Ordering::Release);
            return Ok(());
        }
    }
    Err(())
}

#[cfg(target_arch = "aarch64")]
fn invoke_arm_line_handler<const N: usize>(
    intid: u32,
    intids: &[AtomicU32; N],
    handlers: &[AtomicPtr<()>; N],
    states: &[Spinlock<SpuriousState, Devices>; N],
) -> bool {
    for i in 0..N {
        if intids[i].load(Ordering::Acquire) == intid {
            return invoke_line_ptr(
                handlers[i].load(Ordering::Acquire),
                intid,
                &states[i],
            );
        }
    }
    false
}

#[cfg(target_arch = "aarch64")]
fn arm_line_disabled<const N: usize>(
    intid: u32,
    intids: &[AtomicU32; N],
    states: &[Spinlock<SpuriousState, Devices>; N],
) -> bool {
    for i in 0..N {
        if intids[i].load(Ordering::Acquire) == intid {
            return states[i].lock().disabled();
        }
    }
    false
}

fn invoke_line_ptr(
    raw: *mut (),
    irq: u32,
    state: &Spinlock<SpuriousState, Devices>,
) -> bool {
    if raw.is_null() { return false; }
    if state.lock().disabled() { return false; }
    // SAFETY: raw was installed by a line-handler registration path with LineHandler ABI.
    let f: LineHandler = unsafe { core::mem::transmute(raw) };
    let report = f(irq);
    let disable = state.lock().note(now_ns(), report);
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
        let state = Spinlock::<SpuriousState, Devices>::new(SpuriousState::new());
        for _ in 0..100_000 {
            assert!(invoke_line_ptr(not_mine as *mut (), 0x40, &state));
        }
        assert!(state.lock().disabled());
        assert!(!invoke_line_ptr(not_mine as *mut (), 0x40, &state));
        assert_eq!(HITS.load(Ordering::Relaxed), 100_000);
    }
}
