//! Line-numbered IRQ dispatch tables for Linux-shaped handlers.

#[cfg(target_arch = "aarch64")]
use core::sync::atomic::AtomicU32;
use core::sync::atomic::{AtomicPtr, Ordering};

pub type LineHandler = fn(u32);

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
    invoke_line_ptr(X86_LINE_HANDLERS[idx].load(Ordering::Acquire), vector as u32)
}

#[cfg(target_arch = "x86_64")]
static X86_LINE_HANDLERS: [AtomicPtr<()>; hal_x86_64::VEC_MSI_POOL_LEN] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; hal_x86_64::VEC_MSI_POOL_LEN];

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
    )
}

/// Remove a Linux-shaped fixed-INTID handler.
/// # C: O(N) atomic scan
#[cfg(target_arch = "aarch64")]
pub fn free_arm_irq_line_handler(intid: u32) -> Result<(), ()> {
    free_arm_line_handler(intid, &ARM_FIXED_LINE_INTIDS, &ARM_FIXED_LINE_HANDLERS)
}

/// Dispatch path for Linux-shaped fixed ARM INTID handlers.
/// # C: O(N) atomic scan
#[cfg(target_arch = "aarch64")]
pub fn invoke_arm_irq_line_handler(intid: u32) -> bool {
    invoke_arm_line_handler(intid, &ARM_FIXED_LINE_INTIDS, &ARM_FIXED_LINE_HANDLERS)
}

/// Install a Linux-shaped handler for an ARM MSI INTID.
/// # C: O(N) atomic scan
#[cfg(target_arch = "aarch64")]
pub fn register_msi_line_handler(spi: u32, handler: LineHandler) -> Result<(), ()> {
    request_arm_line_handler(spi, handler, &ARM_MSI_LINE_INTIDS, &ARM_MSI_LINE_HANDLERS)
}

/// Remove a Linux-shaped handler for an ARM MSI INTID.
/// # C: O(N) atomic scan
#[cfg(target_arch = "aarch64")]
pub fn free_msi_line_handler(spi: u32) -> Result<(), ()> {
    free_arm_line_handler(spi, &ARM_MSI_LINE_INTIDS, &ARM_MSI_LINE_HANDLERS)
}

/// Dispatch path for Linux-shaped ARM MSI handlers.
/// # C: O(N) atomic scan
#[cfg(target_arch = "aarch64")]
pub fn invoke_arm_spi_line_handler(intid: u32) -> bool {
    invoke_arm_line_handler(intid, &ARM_MSI_LINE_INTIDS, &ARM_MSI_LINE_HANDLERS)
}

#[cfg(target_arch = "aarch64")]
static ARM_FIXED_LINE_INTIDS: [AtomicU32; ARM_FIXED_LINE_SLOTS] =
    [const { AtomicU32::new(0) }; ARM_FIXED_LINE_SLOTS];
#[cfg(target_arch = "aarch64")]
static ARM_FIXED_LINE_HANDLERS: [AtomicPtr<()>; ARM_FIXED_LINE_SLOTS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; ARM_FIXED_LINE_SLOTS];
#[cfg(target_arch = "aarch64")]
static ARM_MSI_LINE_INTIDS: [AtomicU32; ARM_MSI_LINE_SLOTS] =
    [const { AtomicU32::new(0) }; ARM_MSI_LINE_SLOTS];
#[cfg(target_arch = "aarch64")]
static ARM_MSI_LINE_HANDLERS: [AtomicPtr<()>; ARM_MSI_LINE_SLOTS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; ARM_MSI_LINE_SLOTS];

#[cfg(target_arch = "aarch64")]
fn request_arm_line_handler<const N: usize>(
    intid: u32,
    handler: LineHandler,
    intids: &[AtomicU32; N],
    handlers: &[AtomicPtr<()>; N],
) -> Result<(), ()> {
    if intid == 0 { return Err(()); }
    for i in 0..N {
        if intids[i].load(Ordering::Acquire) == intid {
            handlers[i].store(handler as *mut (), Ordering::Release);
            return Ok(());
        }
    }
    for i in 0..N {
        if intids[i]
            .compare_exchange(0, intid, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
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
) -> Result<(), ()> {
    for i in 0..N {
        if intids[i].load(Ordering::Acquire) == intid {
            handlers[i].store(core::ptr::null_mut(), Ordering::Release);
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
) -> bool {
    for i in 0..N {
        if intids[i].load(Ordering::Acquire) == intid {
            return invoke_line_ptr(handlers[i].load(Ordering::Acquire), intid);
        }
    }
    false
}

fn invoke_line_ptr(raw: *mut (), irq: u32) -> bool {
    if raw.is_null() { return false; }
    // SAFETY: raw was installed by a line-handler registration path with LineHandler ABI.
    let f: LineHandler = unsafe { core::mem::transmute(raw) };
    f(irq);
    true
}
