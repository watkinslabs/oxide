use super::types::*;
use core::ffi::c_void;

const PHY_REGS: usize = 32;
const PHY_MMD_BANKS: usize = 8;

/// Register Linux PHY KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    export("phy_connect_direct", phy_connect_direct as *const () as usize, false);
    export("phy_disconnect", phy_disconnect as *const () as usize, false);
    export("phy_start", phy_start as *const () as usize, false);
    export("phy_stop", phy_stop as *const () as usize, false);
    export("phy_suspend", phy_suspend as *const () as usize, false);
    export("phy_resume", phy_resume as *const () as usize, false);
    export("phy_start_aneg", phy_start_aneg as *const () as usize, false);
    export("phy_init_hw", phy_init_hw as *const () as usize, false);
    export("genphy_soft_reset", genphy_soft_reset as *const () as usize, false);
    export("phy_print_status", phy_print_status as *const () as usize, false);
    export("phy_attached_info", phy_attached_info as *const () as usize, false);
    export("phy_mac_interrupt", phy_mac_interrupt as *const () as usize, false);
    export("phy_do_ioctl_running", phy_do_ioctl_running as *const () as usize, false);
    export("phy_get_pause", phy_get_pause as *const () as usize, false);
    export("phy_set_asym_pause", phy_set_asym_pause as *const () as usize, false);
    export("phy_support_asym_pause", phy_support_asym_pause as *const () as usize, false);
    export("phy_support_eee", phy_support_eee as *const () as usize, false);
    export("phy_ethtool_get_eee", phy_ethtool_get_eee as *const () as usize, false);
    export("phy_ethtool_set_eee", phy_ethtool_set_eee as *const () as usize, false);
    export("phy_ethtool_get_link_ksettings", phy_ethtool_get_link_ksettings as *const () as usize, false);
    export("phy_ethtool_set_link_ksettings", phy_ethtool_set_link_ksettings as *const () as usize, false);
    export("phy_ethtool_nway_reset", phy_ethtool_nway_reset as *const () as usize, false);
    export("phy_set_max_speed", phy_set_max_speed as *const () as usize, false);
    export("phy_speed_down", phy_speed_down as *const () as usize, false);
    export("phy_speed_up", phy_speed_up as *const () as usize, false);
    export("phy_modify", phy_modify as *const () as usize, false);
    export("__phy_modify", __phy_modify as *const () as usize, false);
    export("phy_select_page", phy_select_page as *const () as usize, false);
    export("phy_restore_page", phy_restore_page as *const () as usize, false);
    export("phy_read_paged", phy_read_paged as *const () as usize, false);
    export("phy_write_paged", phy_write_paged as *const () as usize, false);
    export("phy_modify_paged", phy_modify_paged as *const () as usize, false);
    export("phy_write_mmd", phy_write_mmd as *const () as usize, false);
    export("__phy_write_mmd", __phy_write_mmd as *const () as usize, false);
    export("__phy_modify_mmd", __phy_modify_mmd as *const () as usize, false);
    export("mdiobus_get_phy", mdiobus_get_phy as *const () as usize, false);
    export("mdiobus_read", mdiobus_read as *const () as usize, false);
    export("mdiobus_write", mdiobus_write as *const () as usize, false);
}

/// # C: O(1)
unsafe extern "C" fn phy_connect_direct(dev: *mut LinuxNetDevice, phy: *mut LinuxPhyDevice, handler: Option<PhyLinkChange>, interface: u32) -> i32 {
    if dev.is_null() || phy.is_null() { return -LINUX_EINVAL; }
    // SAFETY: caller supplies valid net_device and phy_device storage.
    unsafe {
        (*phy).attached_dev = dev;
        (*phy).link_change = handler;
        (*phy).interface = interface;
        init_defaults(phy);
        (*dev).phydev = phy;
    }
    LINUX_OK
}

/// # C: O(1)
unsafe extern "C" fn phy_disconnect(phy: *mut LinuxPhyDevice) {
    if phy.is_null() { return; }
    // SAFETY: phy points to driver-owned PHY storage.
    unsafe {
        if !(*phy).attached_dev.is_null() { (*(*phy).attached_dev).phydev = core::ptr::null_mut(); }
        (*phy).attached_dev = core::ptr::null_mut();
        (*phy).link = 0;
    }
}

/// # C: O(1)
// SAFETY: set_link null-checks phy and writes only phy->link before notify; the phy_start KPI contract is the phy_device phy_connect_direct attached to netdev->phydev.
unsafe extern "C" fn phy_start(phy: *mut LinuxPhyDevice) { unsafe { set_link(phy, true); } }
/// # C: O(1)
// SAFETY: set_link null-checks phy; phy_stop is called by the MAC driver on the same netdev->phydev it passed to phy_start, so the driver-owned storage is still live.
unsafe extern "C" fn phy_stop(phy: *mut LinuxPhyDevice) { unsafe { set_link(phy, false); } }
/// # C: O(1)
// SAFETY: set_link null-checks phy; the suspend KPI is invoked from the driver PM path on its own netdev->phydev, which the driver keeps allocated across suspend.
unsafe extern "C" fn phy_suspend(phy: *mut LinuxPhyDevice) -> i32 { unsafe { set_link(phy, false); } LINUX_OK }
/// # C: O(1)
// SAFETY: set_link null-checks phy; resume is the paired PM callback on the same driver-owned phy_device that phy_suspend was given.
unsafe extern "C" fn phy_resume(phy: *mut LinuxPhyDevice) -> i32 { unsafe { set_link(phy, true); } LINUX_OK }
/// # C: O(1)
// SAFETY: init_defaults null-checks phy and writes only the speed/duplex/autoneg/link fields of the driver-owned phy_device.
unsafe extern "C" fn phy_start_aneg(phy: *mut LinuxPhyDevice) -> i32 { unsafe { init_defaults(phy); } LINUX_OK }
/// # C: O(1)
// SAFETY: init_defaults null-checks phy; phy_init_hw's KPI contract is a phy_device already attached via phy_connect_direct, so its storage outlives the call.
unsafe extern "C" fn phy_init_hw(phy: *mut LinuxPhyDevice) -> i32 { unsafe { init_defaults(phy); } LINUX_OK }
/// # C: O(1)
// SAFETY: init_defaults null-checks phy; genphy_soft_reset runs as a phy_driver callback and receives that driver's own phy_device.
unsafe extern "C" fn genphy_soft_reset(phy: *mut LinuxPhyDevice) -> i32 { unsafe { init_defaults(phy); } LINUX_OK }
/// # C: O(1)
unsafe extern "C" fn phy_print_status(_phy: *mut LinuxPhyDevice) {}
/// # C: O(1)
unsafe extern "C" fn phy_attached_info(_phy: *mut LinuxPhyDevice) {}
/// # C: O(1)
// SAFETY: notify null-checks phy and re-checks phy->attached_dev before invoking link_change; the MAC driver calls this from its IRQ path on its own phydev.
unsafe extern "C" fn phy_mac_interrupt(phy: *mut LinuxPhyDevice) { unsafe { notify(phy); } }
/// # C: O(1)
unsafe extern "C" fn phy_do_ioctl_running(_dev: *mut LinuxNetDevice, _ifr: *mut c_void, _cmd: i32) -> i32 { LINUX_OK }

/// # C: O(1)
unsafe extern "C" fn phy_get_pause(phy: *mut LinuxPhyDevice, tx_pause: *mut bool, rx_pause: *mut bool) {
    if phy.is_null() { return; }
    // SAFETY: optional pause output pointers are writable when non-NULL.
    unsafe {
        if !tx_pause.is_null() { *tx_pause = (*phy).pause != 0; }
        if !rx_pause.is_null() { *rx_pause = (*phy).pause != 0; }
    }
}

/// # C: O(1)
unsafe extern "C" fn phy_set_asym_pause(phy: *mut LinuxPhyDevice, rx: bool, tx: bool) {
    if phy.is_null() { return; }
    // SAFETY: phy points to driver-owned PHY storage.
    unsafe {
        (*phy).pause = (rx || tx) as u8;
        (*phy).asym_pause = (rx != tx) as u8;
    }
}

/// # C: O(1)
unsafe extern "C" fn phy_support_asym_pause(phy: *mut LinuxPhyDevice) {
    if phy.is_null() { return; }
    // SAFETY: phy points to driver-owned PHY storage.
    unsafe { (*phy).asym_pause = 1; }
}

/// # C: O(1)
unsafe extern "C" fn phy_support_eee(_phy: *mut LinuxPhyDevice) -> i32 { LINUX_OK }
/// # C: O(1)
unsafe extern "C" fn phy_ethtool_get_eee(_phy: *mut LinuxPhyDevice, _data: *mut c_void) -> i32 { LINUX_OK }
/// # C: O(1)
unsafe extern "C" fn phy_ethtool_set_eee(_phy: *mut LinuxPhyDevice, _data: *mut c_void) -> i32 { LINUX_OK }
/// # C: O(1)
unsafe extern "C" fn phy_ethtool_get_link_ksettings(_phy: *mut LinuxPhyDevice, _cmd: *mut c_void) -> i32 { LINUX_OK }
/// # C: O(1)
unsafe extern "C" fn phy_ethtool_set_link_ksettings(_phy: *mut LinuxPhyDevice, _cmd: *const c_void) -> i32 { LINUX_OK }
/// # C: O(1)
// SAFETY: forwards to phy_start_aneg, whose init_defaults null-checks phy; ethtool passes the phydev attached to the net_device being reset.
unsafe extern "C" fn phy_ethtool_nway_reset(phy: *mut LinuxPhyDevice) -> i32 { unsafe { phy_start_aneg(phy) } }

/// # C: O(1)
unsafe extern "C" fn phy_set_max_speed(phy: *mut LinuxPhyDevice, speed: u32) -> i32 {
    if phy.is_null() { return -LINUX_EINVAL; }
    // SAFETY: phy points to driver-owned PHY storage.
    unsafe { (*phy).speed = speed as i32; }
    LINUX_OK
}

/// # C: O(1)
unsafe extern "C" fn phy_speed_down(phy: *mut LinuxPhyDevice, sync: bool) -> i32 {
    let _ = sync;
    // SAFETY: phy_set_max_speed null-checks phy and writes only phy->speed, so forwarding the caller's pointer adds no new requirement.
    unsafe { phy_set_max_speed(phy, 100) }
}

/// # C: O(1)
unsafe extern "C" fn phy_speed_up(phy: *mut LinuxPhyDevice) -> i32 {
    // SAFETY: phy_set_max_speed null-checks phy and writes only phy->speed with the SPEED_1000 constant.
    unsafe { phy_set_max_speed(phy, SPEED_1000 as u32) }
}

/// # C: O(1)
unsafe extern "C" fn phy_modify(phy: *mut LinuxPhyDevice, reg: u32, mask: u16, set: u16) -> i32 {
    // SAFETY: __phy_modify null-checks phy and rejects reg >= PHY_REGS before indexing phy->regs, so this forwarding cannot go out of bounds.
    unsafe { __phy_modify(phy, reg, mask, set) }
}

/// # C: O(1)
unsafe extern "C" fn __phy_modify(phy: *mut LinuxPhyDevice, reg: u32, mask: u16, set: u16) -> i32 {
    if phy.is_null() || reg as usize >= PHY_REGS { return -LINUX_EINVAL; }
    // SAFETY: phy points to driver-owned PHY storage.
    unsafe { (*phy).regs[reg as usize] = ((*phy).regs[reg as usize] & !mask) | set; }
    LINUX_OK
}

/// # C: O(1)
unsafe extern "C" fn phy_select_page(phy: *mut LinuxPhyDevice, page: i32) -> i32 {
    if phy.is_null() { return -LINUX_EINVAL; }
    // SAFETY: phy points to driver-owned PHY storage.
    unsafe {
        let old = (*phy).page;
        (*phy).page = page;
        old
    }
}

/// # C: O(1)
unsafe extern "C" fn phy_restore_page(phy: *mut LinuxPhyDevice, oldpage: i32, ret: i32) -> i32 {
    if !phy.is_null() {
        // SAFETY: phy points to driver-owned PHY storage.
        unsafe { (*phy).page = oldpage; }
    }
    ret
}

/// # C: O(1)
unsafe extern "C" fn phy_read_paged(phy: *mut LinuxPhyDevice, page: i32, reg: u32) -> i32 {
    // SAFETY: phy_select_page null-checks phy itself and only swaps phy->page, returning the previous page or -EINVAL for NULL.
    let old = unsafe { phy_select_page(phy, page) };
    if old < 0 { return old; }
    let val = if phy.is_null() || reg as usize >= PHY_REGS { -LINUX_EINVAL } else {
        // SAFETY: phy points to driver-owned PHY storage.
        unsafe { (*phy).regs[reg as usize] as i32 }
    };
    // SAFETY: phy_restore_page null-checks phy and writes back exactly the page phy_select_page returned above, leaving no other state touched.
    unsafe { phy_restore_page(phy, old, val) }
}

/// # C: O(1)
unsafe extern "C" fn phy_write_paged(phy: *mut LinuxPhyDevice, page: i32, reg: u32, val: u16) -> i32 {
    // SAFETY: phy_select_page null-checks phy; a negative result means phy was NULL and is filtered on the next line before phy->regs is touched.
    let old = unsafe { phy_select_page(phy, page) };
    if old < 0 { return old; }
    let ret = if phy.is_null() || reg as usize >= PHY_REGS { -LINUX_EINVAL } else {
        // SAFETY: phy points to driver-owned PHY storage.
        unsafe { (*phy).regs[reg as usize] = val; }
        LINUX_OK
    };
    // SAFETY: phy_restore_page null-checks phy and restores the page saved by phy_select_page at the top of this function.
    unsafe { phy_restore_page(phy, old, ret) }
}

/// # C: O(1)
unsafe extern "C" fn phy_modify_paged(phy: *mut LinuxPhyDevice, page: i32, reg: u32, mask: u16, set: u16) -> i32 {
    // SAFETY: phy_select_page null-checks phy; the negative return for NULL is filtered on the next line, so the rest of this body runs only for a live phy_device.
    let old = unsafe { phy_select_page(phy, page) };
    if old < 0 { return old; }
    // SAFETY: __phy_modify re-null-checks phy and rejects reg >= PHY_REGS before read-modify-writing phy->regs[reg].
    let ret = unsafe { __phy_modify(phy, reg, mask, set) };
    // SAFETY: phy_restore_page null-checks phy and writes back the page saved into old above, restoring the register bank the caller expects.
    unsafe { phy_restore_page(phy, old, ret) }
}

/// # C: O(1)
unsafe extern "C" fn phy_write_mmd(phy: *mut LinuxPhyDevice, devad: i32, reg: u32, val: u16) -> i32 {
    // SAFETY: __phy_write_mmd null-checks phy and bounds-checks devad against PHY_MMD_BANKS and reg against PHY_REGS before indexing phy->mmd_regs.
    unsafe { __phy_write_mmd(phy, devad, reg, val) }
}

/// # C: O(1)
unsafe extern "C" fn __phy_write_mmd(phy: *mut LinuxPhyDevice, devad: i32, reg: u32, val: u16) -> i32 {
    if phy.is_null() || devad < 0 || devad as usize >= PHY_MMD_BANKS || reg as usize >= PHY_REGS { return -LINUX_EINVAL; }
    // SAFETY: phy points to driver-owned PHY storage.
    unsafe { (*phy).mmd_regs[devad as usize][reg as usize] = val; }
    LINUX_OK
}

/// # C: O(1)
unsafe extern "C" fn __phy_modify_mmd(phy: *mut LinuxPhyDevice, devad: i32, reg: u32, mask: u16, set: u16) -> i32 {
    if phy.is_null() || devad < 0 || devad as usize >= PHY_MMD_BANKS || reg as usize >= PHY_REGS { return -LINUX_EINVAL; }
    // SAFETY: phy points to driver-owned PHY storage.
    unsafe {
        let slot = &mut (*phy).mmd_regs[devad as usize][reg as usize];
        *slot = (*slot & !mask) | set;
    }
    LINUX_OK
}

unsafe fn init_defaults(phy: *mut LinuxPhyDevice) {
    if phy.is_null() { return; }
    // SAFETY: phy points to driver-owned PHY storage.
    unsafe {
        if (*phy).speed == 0 { (*phy).speed = SPEED_1000; }
        (*phy).duplex = DUPLEX_FULL;
        (*phy).autoneg = AUTONEG_ENABLE;
        (*phy).link = 1;
    }
}

unsafe fn set_link(phy: *mut LinuxPhyDevice, up: bool) {
    if phy.is_null() { return; }
    // SAFETY: phy points to driver-owned PHY storage.
    unsafe {
        (*phy).link = up as u8;
        notify(phy);
    }
}

unsafe fn notify(phy: *mut LinuxPhyDevice) {
    if phy.is_null() { return; }
    // SAFETY: phy points to driver-owned PHY storage.
    unsafe {
        if let Some(cb) = (*phy).link_change {
            if !(*phy).attached_dev.is_null() { cb((*phy).attached_dev); }
        }
    }
}

/// # C: O(1)
unsafe extern "C" fn mdiobus_get_phy(_bus: *mut c_void, _addr: i32) -> *mut LinuxPhyDevice {
    core::ptr::null_mut()
}

/// # C: O(1)
unsafe extern "C" fn mdiobus_read(_bus: *mut c_void, _addr: i32, _regnum: u32) -> i32 {
    0
}

/// # C: O(1)
unsafe extern "C" fn mdiobus_write(_bus: *mut c_void, _addr: i32, _regnum: u32, _val: u16) -> i32 {
    LINUX_OK
}
