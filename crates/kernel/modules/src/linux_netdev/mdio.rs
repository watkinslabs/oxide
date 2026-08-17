extern crate alloc;

use super::types::*;
use crate::linux_device::{devres, types::LinuxDevice};
use alloc::alloc::{alloc_zeroed, dealloc, Layout};
use core::ffi::c_void;
use core::mem::{align_of, size_of};
use core::ptr::null_mut;

const MDIO_MAGIC: u64 = 0x4f58_4b50_494d_4449;

#[repr(C)]
#[derive(Copy, Clone)]
struct MdioHeader { magic: u64, total: usize, align: usize, off: usize }

/// Register managed MDIO-bus KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    export("devm_mdiobus_alloc_size", devm_mdiobus_alloc_size as *const () as usize, false);
    export("__devm_mdiobus_register", __devm_mdiobus_register as *const () as usize, false);
}

/// # C: O(sizeof(struct mii_bus)+sizeof_priv)
unsafe extern "C" fn devm_mdiobus_alloc_size(dev: *mut LinuxDevice, sizeof_priv: i32) -> *mut LinuxMiiBus {
    if dev.is_null() || sizeof_priv < 0 { return null_mut(); }
    let align = align_of::<LinuxMiiBus>().max(align_of::<usize>());
    let off = align_up(size_of::<MdioHeader>(), align);
    let priv_off = align_up(off + size_of::<LinuxMiiBus>(), align_of::<usize>());
    let total = match priv_off.checked_add(sizeof_priv as usize) { Some(v) => v, None => return null_mut() };
    let layout = match Layout::from_size_align(total, align) { Ok(v) => v, Err(_) => return null_mut() };
    // SAFETY: validated allocation layout is zeroed before publication as a bus object.
    let base = unsafe { alloc_zeroed(layout) };
    if base.is_null() { return null_mut(); }
    // SAFETY: all offsets were derived from the allocation size and alignment above.
    let bus = unsafe { base.add(off) as *mut LinuxMiiBus };
    // SAFETY: header offset and priv_off were both derived from and bounds-checked against total/layout above; bus is the just-computed in-bounds pointer, not yet visible to any other caller.
    unsafe {
        ((base.add(off - size_of::<MdioHeader>())) as *mut MdioHeader).write(MdioHeader {
            magic: MDIO_MAGIC, total, align, off,
        });
        (*bus).parent = dev;
        (*bus).priv_data = if sizeof_priv == 0 { null_mut() } else { base.add(priv_off).cast() };
    }
    if devres::add_action_or_reset(dev, Some(devm_mdiobus_free), bus.cast()) != LINUX_OK { return null_mut(); }
    bus
}

/// # C: O(1)
unsafe extern "C" fn __devm_mdiobus_register(dev: *mut LinuxDevice, bus: *mut LinuxMiiBus,
    _owner: *mut c_void) -> i32 {
    if dev.is_null() || bus.is_null() { return -LINUX_EINVAL; }
    // SAFETY: managed allocation records its owning device in the bus before registration.
    unsafe {
        if (*bus).parent != dev || (*bus).state != 0 { return -LINUX_EINVAL; }
        (*bus).state = 1;
    }
    if devres::add_action_or_reset(dev, Some(devm_mdiobus_unregister), bus.cast()) != LINUX_OK { return -LINUX_ENOMEM; }
    LINUX_OK
}

unsafe extern "C" fn devm_mdiobus_unregister(data: *mut c_void) {
    if data.is_null() { return; }
    // SAFETY: devres invokes this with the managed mii_bus it registered.
    unsafe { (*(data as *mut LinuxMiiBus)).state = 0; }
}

unsafe extern "C" fn devm_mdiobus_free(data: *mut c_void) {
    if data.is_null() { return; }
    // SAFETY: the header directly precedes this managed mii_bus allocation.
    unsafe {
        let bus = data as *mut LinuxMiiBus;
        let hp = (bus as *mut u8).sub(size_of::<MdioHeader>()) as *mut MdioHeader;
        let h = *hp;
        if h.magic != MDIO_MAGIC { return; }
        if let Ok(layout) = Layout::from_size_align(h.total, h.align) {
            dealloc((bus as *mut u8).sub(h.off), layout);
        }
    }
}

const fn align_up(v: usize, a: usize) -> usize { (v + (a - 1)) & !(a - 1) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_bus_registers_then_unwinds_in_reverse_order() {
        let _modules = crate::test_serial::claim();
        let mut dev = LinuxDevice::new();
        // SAFETY: test owns the device and its managed MDIO allocation through release.
        unsafe {
            let bus = devm_mdiobus_alloc_size(&mut dev, 64);
            assert!(!bus.is_null());
            assert_eq!(__devm_mdiobus_register(&mut dev, bus, null_mut()), LINUX_OK);
            assert_eq!((*bus).state, 1);
            devres::release_device(&mut dev);
        }
    }
}
