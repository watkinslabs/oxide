use super::core::{cdev_add, cdev_del, cdev_init, unregister_chrdev_region, volatile_write_u32};
use super::types::*;
use sync::{Modules as ModulesLockClass, Spinlock};

const MAX_MISC_MINORS: usize = LINUX_MISC_MAX_DYNAMIC_MINOR as usize + 1;

static MISC_MINORS: Spinlock<[usize; MAX_MISC_MINORS], ModulesLockClass> =
    Spinlock::new([0; MAX_MISC_MINORS]);

/// Register Linux miscdevice KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    export("misc_register",   misc_register   as *const () as usize, false);
    export("misc_deregister", misc_deregister as *const () as usize, false);
}

extern "C" fn misc_register(misc: *mut LinuxMiscDevice) -> i32 {
    if misc.is_null() { return -LINUX_EINVAL; }
    // SAFETY: misc is caller-owned Linux struct miscdevice storage.
    let (requested, fops) = unsafe { ((*misc).minor, (*misc).fops) };
    if fops.is_null() { return -LINUX_EINVAL; }
    let minor = if requested == LINUX_MISC_DYNAMIC_MINOR {
        match allocate_misc_minor(misc) { Some(v) => v, None => return -LINUX_EBUSY }
    } else {
        if requested < LINUX_MISC_MIN_VALID_MINOR || requested as u32 > LINUX_MISC_MAX_DYNAMIC_MINOR { return -LINUX_EINVAL; }
        if !claim_misc_minor(requested as u32, misc) { return -LINUX_EBUSY; }
        requested as u32
    };
    // SAFETY: misc is valid caller-owned storage.
    unsafe {
        (*misc).minor = minor as i32;
        if (*misc).mode == 0 { (*misc).mode = LINUX_MISC_DEFAULT_MODE; }
        cdev_init(&mut (*misc).cdev, fops);
    }
    let rc = cdev_add(misc_cdev(misc), mkdev(LINUX_MISC_MAJOR, minor), LINUX_MISC_MINOR_COUNT);
    if rc != LINUX_OK {
        release_misc_minor(minor, misc);
        return rc;
    }
    // SAFETY: misc is valid caller-owned storage.
    unsafe { (*misc).registered = LINUX_FIELD_SET; }
    LINUX_OK
}

extern "C" fn misc_deregister(misc: *mut LinuxMiscDevice) -> i32 {
    if misc.is_null() { return -LINUX_EINVAL; }
    // SAFETY: misc is caller-owned Linux struct miscdevice storage.
    let minor = unsafe { (*misc).minor };
    if minor < LINUX_OK { return -LINUX_EINVAL; }
    cdev_del(misc_cdev(misc));
    release_misc_minor(minor as u32, misc);
    // SAFETY: misc is valid caller-owned storage.
    unsafe { (*misc).registered = LINUX_FIELD_CLEAR; }
    LINUX_OK
}

fn allocate_misc_minor(misc: *mut LinuxMiscDevice) -> Option<u32> {
    for minor in LINUX_MISC_FIRST_DYNAMIC_MINOR..=LINUX_MISC_MAX_DYNAMIC_MINOR {
        if claim_misc_minor(minor, misc) { return Some(minor); }
    }
    None
}

fn claim_misc_minor(minor: u32, misc: *mut LinuxMiscDevice) -> bool {
    let mut g = MISC_MINORS.lock();
    let idx = minor as usize;
    if g[idx] != 0 { return false; }
    g[idx] = misc as usize;
    true
}

fn release_misc_minor(minor: u32, misc: *mut LinuxMiscDevice) {
    if minor > LINUX_MISC_MAX_DYNAMIC_MINOR { return; }
    let mut g = MISC_MINORS.lock();
    let idx = minor as usize;
    if g[idx] == misc as usize { g[idx] = 0; }
    unregister_chrdev_region(mkdev(LINUX_MISC_MAJOR, minor), LINUX_MISC_MINOR_COUNT);
    volatile_write_u32(registered_ptr(misc), LINUX_FIELD_CLEAR);
}

fn misc_cdev(misc: *mut LinuxMiscDevice) -> *mut LinuxCdev {
    if misc.is_null() { core::ptr::null_mut() } else {
        // SAFETY: misc is checked non-null and cdev is an embedded field.
        unsafe { &mut (*misc).cdev }
    }
}

fn registered_ptr(misc: *mut LinuxMiscDevice) -> *mut u32 {
    if misc.is_null() { core::ptr::null_mut() } else {
        // SAFETY: misc is checked non-null and registered is an embedded field.
        unsafe { &mut (*misc).registered }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux_chrdev::types::LinuxFileOperations;
    use core::ptr::null_mut;

    static FOPS: LinuxFileOperations = LinuxFileOperations {
        owner: null_mut(),
        open: None,
        read: None,
        write: None,
        unlocked_ioctl: None,
        release: None,
        poll: None,
        mmap: None,
        llseek: null_mut(),
    };

    fn new_misc() -> LinuxMiscDevice {
        LinuxMiscDevice {
            minor: LINUX_MISC_DYNAMIC_MINOR,
            name: core::ptr::null(),
            fops: &FOPS,
            parent: null_mut(),
            this_device: null_mut(),
            mode: 0,
            nodename: core::ptr::null(),
            cdev: LinuxCdev {
                ops: core::ptr::null(),
                owner: null_mut(),
                dev: 0,
                count: 0,
                added: LINUX_FIELD_CLEAR,
                private: null_mut(),
            },
            registered: LINUX_FIELD_CLEAR,
        }
    }

    #[test]
    fn misc_register_claims_minor_and_cdev() {
        let mut misc = new_misc();
        assert_eq!(misc_register(&mut misc), LINUX_OK);
        assert_ne!(misc.minor, LINUX_MISC_DYNAMIC_MINOR);
        assert_eq!(misc.mode, LINUX_MISC_DEFAULT_MODE);
        assert_eq!(misc.registered, LINUX_FIELD_SET);
        assert!(vfs::lookup_chrdev(vfs::Devt::from_kdev(mkdev(LINUX_MISC_MAJOR, misc.minor as u32))).is_some());
        assert_eq!(misc_deregister(&mut misc), LINUX_OK);
        assert_eq!(misc.registered, LINUX_FIELD_CLEAR);
        assert!(vfs::lookup_chrdev(vfs::Devt::from_kdev(mkdev(LINUX_MISC_MAJOR, misc.minor as u32))).is_none());
    }
}
