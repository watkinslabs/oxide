use super::core::resource_len;
use super::types::*;
use core::ffi::c_char;

/// Register display-aperture PCI KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    crate::symtab::export("aperture_remove_conflicting_devices", aperture_remove_conflicting_devices as *const () as usize, false);
    crate::symtab::export("aperture_remove_conflicting_pci_devices", aperture_remove_conflicting_pci_devices as *const () as usize, false);
}

fn remove_range(base: u64, bytes: u64) -> i32 {
    match fbdev::remove_conflicting_apertures(base, bytes) {
        Ok(_) => LINUX_OK,
        Err(fbdev::ApertureError::Inval) => -LINUX_EINVAL,
        Err(fbdev::ApertureError::Busy) => -LINUX_EBUSY,
    }
}

extern "C" fn aperture_remove_conflicting_devices(base: u64, bytes: u64, _name: *const c_char) -> i32 {
    remove_range(base, bytes)
}

extern "C" fn aperture_remove_conflicting_pci_devices(dev: *mut LinuxPciDev, _name: *const c_char) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    // SAFETY: dev is checked non-null above; a module receives only the live
    // facade allocated for its bound PCI function, so its resource table is readable.
    let resources = unsafe { &(&(*dev).resource)[..PCI_STD_NUM_BARS] };
    for res in resources {
        if res.flags & pci::IORESOURCE_MEM == 0 { continue; }
        let rc = remove_range(res.start, resource_len(*res));
        if rc != LINUX_OK { return rc; }
    }
    LINUX_OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static DETACHED: AtomicBool = AtomicBool::new(false);

    fn detach(_key: fbdev::ApertureKey) { DETACHED.store(true, Ordering::Release); }

    #[test]
    fn pci_helper_ignores_non_memory_bars() {
        let _serial = TEST_LOCK.lock().unwrap();
        // SAFETY: LinuxPciDev is an FFI facade whose zero representation is valid;
        // this test initializes the only resource fields inspected by the helper.
        let mut dev: LinuxPciDev = unsafe { core::mem::MaybeUninit::zeroed().assume_init() };
        dev.resource[0].start = 0x1000;
        dev.resource[0].end = 0x1fff;
        dev.resource[0].flags = pci::IORESOURCE_IO;
        assert_eq!(aperture_remove_conflicting_pci_devices(&mut dev, core::ptr::null()), LINUX_OK);
    }

    #[test]
    fn pci_helper_rejects_null_device() {
        assert_eq!(aperture_remove_conflicting_pci_devices(core::ptr::null_mut(), core::ptr::null()), -LINUX_EINVAL);
    }

    #[test]
    fn aperture_kpi_exports_both_driver_entry_points() {
        let _modules = crate::test_serial::claim();
        export_symbols();
        assert!(crate::symtab::is_exported("aperture_remove_conflicting_devices"));
        assert!(crate::symtab::is_exported("aperture_remove_conflicting_pci_devices"));
    }

    #[test]
    fn pci_helper_removes_overlapping_memory_bar_owner() {
        let _serial = TEST_LOCK.lock().unwrap();
        DETACHED.store(false, Ordering::Release);
        let key = fbdev::acquire_aperture(0x4000, 0x1000, detach).unwrap();
        // SAFETY: LinuxPciDev is an FFI facade whose zero representation is valid;
        // this test initializes the only resource fields inspected by the helper.
        let mut dev: LinuxPciDev = unsafe { core::mem::MaybeUninit::zeroed().assume_init() };
        dev.resource[0].start = 0x4800;
        dev.resource[0].end = 0x4fff;
        dev.resource[0].flags = pci::IORESOURCE_MEM;
        assert_eq!(aperture_remove_conflicting_pci_devices(&mut dev, core::ptr::null()), LINUX_OK);
        assert!(DETACHED.load(Ordering::Acquire));
        assert!(!fbdev::release_aperture(key));
    }
}
