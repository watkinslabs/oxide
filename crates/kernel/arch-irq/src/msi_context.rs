//! Binding-owned hard-IRQ MSI context dispatch.

use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

#[cfg(target_arch = "x86_64")]
static X86_HANDLERS: [AtomicPtr<()>; hal_x86_64::VEC_MSI_POOL_LEN] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; hal_x86_64::VEC_MSI_POOL_LEN];
#[cfg(target_arch = "x86_64")]
static X86_ARGS: [AtomicUsize; hal_x86_64::VEC_MSI_POOL_LEN] =
    [const { AtomicUsize::new(0) }; hal_x86_64::VEC_MSI_POOL_LEN];

#[cfg(target_arch = "x86_64")]
pub(crate) fn register_x86(vector: u8, handler: fn(usize), arg: usize) -> Result<(), ()> {
    if vector < hal_x86_64::VEC_MSI_POOL_FIRST || vector > hal_x86_64::VEC_MSI_POOL_LAST { return Err(()); }
    let idx = (vector - hal_x86_64::VEC_MSI_POOL_FIRST) as usize;
    X86_ARGS[idx].store(arg, Ordering::Release);
    X86_HANDLERS[idx].store(handler as *mut (), Ordering::Release);
    Ok(())
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn clear_x86(vector: u8) {
    let idx = (vector - hal_x86_64::VEC_MSI_POOL_FIRST) as usize;
    X86_HANDLERS[idx].store(core::ptr::null_mut(), Ordering::Release);
    X86_ARGS[idx].store(0, Ordering::Release);
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn invoke_x86(vector: u8) -> bool {
    let idx = (vector - hal_x86_64::VEC_MSI_POOL_FIRST) as usize;
    let handler = X86_HANDLERS[idx].load(Ordering::Acquire);
    if handler.is_null() { return false; }
    let arg = X86_ARGS[idx].load(Ordering::Acquire);
    // SAFETY: register_x86 publishes this exact fn(usize) before the handler pointer.
    let f: fn(usize) = unsafe { core::mem::transmute(handler) };
    f(arg);
    true
}

#[cfg(target_arch = "aarch64")]
static ARM_HANDLERS: [AtomicPtr<()>; super::ARM_MSI_SLOTS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; super::ARM_MSI_SLOTS];
#[cfg(target_arch = "aarch64")]
static ARM_ARGS: [AtomicUsize; super::ARM_MSI_SLOTS] =
    [const { AtomicUsize::new(0) }; super::ARM_MSI_SLOTS];

#[cfg(target_arch = "aarch64")]
pub(crate) fn register_arm(spi: u32, handler: fn(usize), arg: usize) -> Result<(), ()> {
    for i in 0..super::ARM_MSI_SLOTS {
        if super::ARM_MSI_SPIS[i].load(Ordering::Acquire) == spi {
            ARM_ARGS[i].store(arg, Ordering::Release);
            ARM_HANDLERS[i].store(handler as *mut (), Ordering::Release);
            return Ok(());
        }
    }
    Err(())
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn clear_arm(slot: usize) {
    ARM_HANDLERS[slot].store(core::ptr::null_mut(), Ordering::Release);
    ARM_ARGS[slot].store(0, Ordering::Release);
}

/// Dispatch one binding-owned MSI context or its bare legacy handler.
/// # C: O(N_irq_slots)
#[cfg(target_arch = "aarch64")]
pub fn invoke_arm_spi_handler(intid: u32) -> bool {
    for i in 0..super::ARM_MSI_SLOTS {
        if super::ARM_MSI_SPIS[i].load(Ordering::Acquire) != intid { continue; }
        let handler = ARM_HANDLERS[i].load(Ordering::Acquire);
        if !handler.is_null() {
            let arg = ARM_ARGS[i].load(Ordering::Acquire);
            // SAFETY: register_arm publishes this exact fn(usize) before the handler pointer.
            let f: fn(usize) = unsafe { core::mem::transmute(handler) };
            f(arg);
            return true;
        }
        let raw = super::ARM_MSI_HANDS[i].load(Ordering::Acquire);
        if raw.is_null() { return false; }
        // SAFETY: register_msi_handler publishes this exact fn() for the selected SPI.
        let f: fn() = unsafe { core::mem::transmute(raw) };
        f();
        return true;
    }
    false
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use core::sync::atomic::{AtomicUsize, Ordering};

    static SEEN: AtomicUsize = AtomicUsize::new(0);

    fn handler(arg: usize) { SEEN.store(arg, Ordering::Release); }

    #[test]
    fn vector_dispatches_its_owned_context_not_a_global_lookup() {
        let vector = hal_x86_64::VEC_MSI_POOL_FIRST;
        super::register_x86(vector, handler, 0x34).expect("pool vector accepts context");
        assert!(super::invoke_x86(vector));
        assert_eq!(SEEN.load(Ordering::Acquire), 0x34);
        super::clear_x86(vector);
        assert!(!super::invoke_x86(vector));
    }
}
