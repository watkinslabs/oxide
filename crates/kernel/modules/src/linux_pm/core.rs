use super::types::*;
use crate::linux_device::types::LinuxDevice;

/// Register Linux PM KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("dev_pm_suspend",                       dev_pm_suspend                       as *const () as usize),
        ("dev_pm_resume",                        dev_pm_resume                        as *const () as usize),
        ("pm_runtime_enable",                    pm_runtime_enable                    as *const () as usize),
        ("pm_runtime_disable",                   pm_runtime_disable                   as *const () as usize),
        ("pm_runtime_enabled",                   pm_runtime_enabled                   as *const () as usize),
        ("pm_runtime_get_sync",                  pm_runtime_get_sync                  as *const () as usize),
        ("pm_runtime_put",                       pm_runtime_put                       as *const () as usize),
        ("pm_runtime_put_sync",                  pm_runtime_put_sync                  as *const () as usize),
        ("pm_runtime_put_noidle",                pm_runtime_put_noidle                as *const () as usize),
        ("pm_runtime_get_noresume",              pm_runtime_get_noresume              as *const () as usize),
        ("pm_runtime_get_if_in_use",             pm_runtime_get_if_in_use             as *const () as usize),
        ("pm_runtime_resume",                    pm_runtime_resume                    as *const () as usize),
        ("pm_runtime_suspend",                   pm_runtime_suspend                   as *const () as usize),
        ("pm_runtime_set_active",                pm_runtime_set_active                as *const () as usize),
        ("pm_runtime_set_suspended",             pm_runtime_set_suspended             as *const () as usize),
        ("pm_runtime_active",                    pm_runtime_active                    as *const () as usize),
        ("pm_runtime_suspended",                 pm_runtime_suspended                 as *const () as usize),
        ("pm_runtime_forbid",                    pm_runtime_forbid                    as *const () as usize),
        ("pm_runtime_allow",                     pm_runtime_allow                     as *const () as usize),
        ("pm_runtime_mark_last_busy",            pm_runtime_mark_last_busy            as *const () as usize),
        ("pm_runtime_autosuspend_expiration",    pm_runtime_autosuspend_expiration    as *const () as usize),
        ("pm_runtime_set_autosuspend_delay",     pm_runtime_set_autosuspend_delay     as *const () as usize),
        ("pm_runtime_use_autosuspend",           pm_runtime_use_autosuspend           as *const () as usize),
        ("pm_runtime_dont_use_autosuspend",      pm_runtime_dont_use_autosuspend      as *const () as usize),
        ("pm_schedule_suspend",                  pm_schedule_suspend                  as *const () as usize),
        ("device_init_wakeup",                   device_init_wakeup                   as *const () as usize),
        ("device_set_wakeup_capable",            device_set_wakeup_capable            as *const () as usize),
        ("device_can_wakeup",                    device_can_wakeup                    as *const () as usize),
        ("device_may_wakeup",                    device_may_wakeup                    as *const () as usize),
        ("device_wakeup_enable",                 device_wakeup_enable                 as *const () as usize),
        ("device_wakeup_disable",                device_wakeup_disable                as *const () as usize),
        ("pm_wakeup_event",                      pm_wakeup_event                      as *const () as usize),
        ("pm_stay_awake",                        pm_stay_awake                        as *const () as usize),
        ("pm_relax",                             pm_relax                             as *const () as usize),
    ] { export(name, addr, false); }
}

extern "C" fn dev_pm_suspend(dev: *mut LinuxDevice) -> i32 {
    pm_call(dev, |ops| ops.suspend).map(|rc| {
        if rc == LINUX_OK { set_status(dev, RPM_SUSPENDED); }
        rc
    }).unwrap_or(LINUX_OK)
}

extern "C" fn dev_pm_resume(dev: *mut LinuxDevice) -> i32 {
    pm_call(dev, |ops| ops.resume).map(|rc| {
        if rc == LINUX_OK { set_status(dev, RPM_ACTIVE); }
        rc
    }).unwrap_or(LINUX_OK)
}

extern "C" fn pm_runtime_enable(dev: *mut LinuxDevice) {
    if dev.is_null() { return; }
    // SAFETY: dev points at a caller-owned Linux struct device.
    unsafe { (*dev).power.disable_depth = 0; }
}

extern "C" fn pm_runtime_disable(dev: *mut LinuxDevice) {
    if dev.is_null() { return; }
    // SAFETY: dev points at a caller-owned Linux struct device.
    unsafe { (*dev).power.disable_depth = (*dev).power.disable_depth.saturating_add(1); }
}

extern "C" fn pm_runtime_enabled(dev: *mut LinuxDevice) -> bool {
    // SAFETY: `&&` short-circuits, so the read runs only once dev is known non-null; power is the LinuxDevPmInfo embedded by value in the caller's struct device, zeroed at LinuxDevPmInfo::new().
    !dev.is_null() && unsafe { (*dev).power.disable_depth == 0 }
}

extern "C" fn pm_runtime_get_sync(dev: *mut LinuxDevice) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    pm_runtime_get_noresume(dev);
    let rc = pm_runtime_resume(dev);
    if rc < LINUX_OK {
        let _ = pm_runtime_put_noidle(dev);
    }
    rc
}

extern "C" fn pm_runtime_put(dev: *mut LinuxDevice) -> i32 {
    pm_runtime_put_sync(dev)
}

extern "C" fn pm_runtime_put_sync(dev: *mut LinuxDevice) -> i32 {
    let rc = pm_runtime_put_noidle(dev);
    if rc < LINUX_OK { return rc; }
    if usage(dev) == 0 { pm_runtime_suspend(dev) } else { LINUX_OK }
}

extern "C" fn pm_runtime_put_noidle(dev: *mut LinuxDevice) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    // SAFETY: dev points at a caller-owned Linux struct device.
    unsafe {
        if (*dev).power.usage_count == 0 { return -LINUX_EBUSY; }
        (*dev).power.usage_count -= 1;
    }
    LINUX_OK
}

extern "C" fn pm_runtime_get_noresume(dev: *mut LinuxDevice) {
    if dev.is_null() { return; }
    // SAFETY: dev points at a caller-owned Linux struct device.
    unsafe { (*dev).power.usage_count = (*dev).power.usage_count.saturating_add(1); }
}

extern "C" fn pm_runtime_get_if_in_use(dev: *mut LinuxDevice) -> i32 {
    if dev.is_null() { return LINUX_FALSE; }
    // SAFETY: dev points at a caller-owned Linux struct device.
    unsafe {
        if (*dev).power.disable_depth != 0 || (*dev).power.usage_count == 0 { return LINUX_FALSE; }
        (*dev).power.usage_count = (*dev).power.usage_count.saturating_add(1);
    }
    LINUX_TRUE
}

extern "C" fn pm_runtime_resume(dev: *mut LinuxDevice) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    if !pm_runtime_enabled(dev) { return LINUX_OK; }
    if pm_runtime_active(dev) { return LINUX_OK; }
    set_status(dev, RPM_RESUMING);
    let rc = pm_call(dev, |ops| ops.runtime_resume).unwrap_or(LINUX_OK);
    set_error(dev, rc);
    set_status(dev, if rc == LINUX_OK { RPM_ACTIVE } else { RPM_SUSPENDED });
    rc
}

extern "C" fn pm_runtime_suspend(dev: *mut LinuxDevice) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    if !pm_runtime_enabled(dev) { return LINUX_OK; }
    if pm_runtime_suspended(dev) { return LINUX_OK; }
    set_status(dev, RPM_SUSPENDING);
    let rc = pm_call(dev, |ops| ops.runtime_suspend).unwrap_or(LINUX_OK);
    set_error(dev, rc);
    set_status(dev, if rc == LINUX_OK { RPM_SUSPENDED } else { RPM_ACTIVE });
    rc
}

extern "C" fn pm_runtime_set_active(dev: *mut LinuxDevice) { set_status(dev, RPM_ACTIVE); }
extern "C" fn pm_runtime_set_suspended(dev: *mut LinuxDevice) { set_status(dev, RPM_SUSPENDED); }
extern "C" fn pm_runtime_active(dev: *mut LinuxDevice) -> bool { status(dev) == Some(RPM_ACTIVE) }
extern "C" fn pm_runtime_suspended(dev: *mut LinuxDevice) -> bool { status(dev) == Some(RPM_SUSPENDED) }

extern "C" fn pm_runtime_forbid(dev: *mut LinuxDevice) { pm_runtime_disable(dev); }
extern "C" fn pm_runtime_allow(dev: *mut LinuxDevice) { pm_runtime_enable(dev); }

extern "C" fn pm_runtime_mark_last_busy(dev: *mut LinuxDevice) {
    if dev.is_null() { return; }
    // SAFETY: dev points at a caller-owned Linux struct device.
    unsafe { (*dev).power.last_busy = (*dev).power.last_busy.saturating_add(PM_BUSY_TICK); }
}

extern "C" fn pm_runtime_autosuspend_expiration(dev: *mut LinuxDevice) -> usize {
    if dev.is_null() { return 0; }
    // SAFETY: dev points at a caller-owned Linux struct device.
    unsafe { (*dev).power.last_busy.saturating_add((*dev).power.autosuspend_delay.max(0) as usize) }
}

extern "C" fn pm_runtime_set_autosuspend_delay(dev: *mut LinuxDevice, delay: i32) {
    if dev.is_null() { return; }
    // SAFETY: dev points at a caller-owned Linux struct device.
    unsafe { (*dev).power.autosuspend_delay = delay; }
}

extern "C" fn pm_runtime_use_autosuspend(dev: *mut LinuxDevice) {
    if dev.is_null() { return; }
    // SAFETY: dev points at a caller-owned Linux struct device.
    unsafe { (*dev).power.use_autosuspend = true; }
}

extern "C" fn pm_runtime_dont_use_autosuspend(dev: *mut LinuxDevice) {
    if dev.is_null() { return; }
    // SAFETY: dev points at a caller-owned Linux struct device.
    unsafe { (*dev).power.use_autosuspend = false; }
}

extern "C" fn pm_schedule_suspend(dev: *mut LinuxDevice, _delay: u32) -> i32 {
    pm_runtime_suspend(dev)
}

extern "C" fn device_init_wakeup(dev: *mut LinuxDevice, enable: bool) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    device_set_wakeup_capable(dev, true);
    if enable { device_wakeup_enable(dev) } else { device_wakeup_disable(dev) }
}

extern "C" fn device_set_wakeup_capable(dev: *mut LinuxDevice, capable: bool) {
    if dev.is_null() { return; }
    // SAFETY: dev points at a caller-owned Linux struct device.
    unsafe {
        (*dev).power.can_wakeup = capable;
        if !capable { (*dev).power.wakeup_enabled = false; }
    }
}

extern "C" fn device_can_wakeup(dev: *mut LinuxDevice) -> bool {
    // SAFETY: `&&` short-circuits past the read for a null dev; can_wakeup is a bool inside the by-value LinuxDevPmInfo, so no further pointer is followed.
    !dev.is_null() && unsafe { (*dev).power.can_wakeup }
}

extern "C" fn device_may_wakeup(dev: *mut LinuxDevice) -> bool {
    // SAFETY: the outer `&&` gates both reads on dev being non-null; both fields are bools inside the by-value LinuxDevPmInfo that device_set_wakeup_capable keeps consistent (clearing wakeup_enabled whenever can_wakeup goes false).
    !dev.is_null() && unsafe { (*dev).power.can_wakeup && (*dev).power.wakeup_enabled }
}

extern "C" fn device_wakeup_enable(dev: *mut LinuxDevice) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    if !device_can_wakeup(dev) { return -LINUX_EINVAL; }
    // SAFETY: dev points at a caller-owned Linux struct device.
    unsafe { (*dev).power.wakeup_enabled = true; }
    LINUX_OK
}

extern "C" fn device_wakeup_disable(dev: *mut LinuxDevice) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    // SAFETY: dev points at a caller-owned Linux struct device.
    unsafe { (*dev).power.wakeup_enabled = false; }
    LINUX_OK
}

extern "C" fn pm_wakeup_event(dev: *mut LinuxDevice, _msec: u32) { pm_runtime_mark_last_busy(dev); }
extern "C" fn pm_stay_awake(dev: *mut LinuxDevice) { pm_runtime_mark_last_busy(dev); }
extern "C" fn pm_relax(dev: *mut LinuxDevice) { pm_runtime_mark_last_busy(dev); }

fn pm_call(dev: *mut LinuxDevice, f: fn(&LinuxDevPmOps) -> Option<PmCb>) -> Option<i32> {
    if dev.is_null() { return Some(-LINUX_EINVAL); }
    // SAFETY: dev and its driver are caller-owned Linux KPI structs.
    unsafe {
        let driver = (*dev).driver;
        if driver.is_null() || (*driver).pm.is_null() { return None; }
        f(&*(*driver).pm).map(|cb| cb(dev))
    }
}

fn set_status(dev: *mut LinuxDevice, st: i32) {
    if dev.is_null() { return; }
    // SAFETY: dev points at a caller-owned Linux struct device.
    unsafe { (*dev).power.runtime_status = st; }
}

fn set_error(dev: *mut LinuxDevice, rc: i32) {
    if dev.is_null() { return; }
    // SAFETY: dev points at a caller-owned Linux struct device.
    unsafe { (*dev).power.runtime_error = if rc == LINUX_OK { LINUX_OK } else { rc }; }
}

fn status(dev: *mut LinuxDevice) -> Option<i32> {
    if dev.is_null() { None } else {
        // SAFETY: dev points at a caller-owned Linux struct device.
        Some(unsafe { (*dev).power.runtime_status })
    }
}

fn usage(dev: *mut LinuxDevice) -> i32 {
    if dev.is_null() { 0 } else {
        // SAFETY: dev points at a caller-owned Linux struct device.
        unsafe { (*dev).power.usage_count }
    }
}

#[cfg(test)]
mod tests;
