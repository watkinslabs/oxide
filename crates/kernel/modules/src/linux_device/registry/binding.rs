use super::*;

pub(super) fn bind_driver(driver: usize) -> i32 {
    let mut devs = [0usize; MAX_BIND_BATCH];
    let mut n = 0usize;
    let bus = driver_bus(driver);
    {
        let g = DEVICE_STATE.lock();
        for rec in g.iter().flatten() {
            if n == MAX_BIND_BATCH { break; }
            if rec.added && rec.bound_driver == 0 && device_bus(rec.ptr) == bus {
                devs[n] = rec.ptr;
                n += 1;
            }
        }
    }
    for dev in devs.iter().take(n) {
        let rc = probe(driver, *dev);
        if rc == LINUX_OK { bind_record(*dev, driver); }
        else { return rc; }
    }
    LINUX_OK
}
pub(super) fn bind_device(dev: usize) -> i32 {
    let bus = device_bus(dev);
    let mut drivers = [0usize; MAX_BIND_BATCH];
    let mut n = 0usize;
    {
        let g = DRIVERS.lock();
        for rec in g.iter().flatten() {
            if n == MAX_BIND_BATCH { break; }
            if driver_bus(rec.ptr) == bus {
                drivers[n] = rec.ptr;
                n += 1;
            }
        }
    }
    for driver in drivers.iter().take(n) {
        let rc = probe(*driver, dev);
        if rc == LINUX_OK {
            bind_record(dev, *driver);
            return LINUX_OK;
        }
    }
    LINUX_OK
}

pub(super) fn unbind_device(dev: usize) -> i32 {
    let driver = {
        let mut g = DEVICE_STATE.lock();
        let Some(rec) = g.iter_mut().flatten().find(|r| r.ptr == dev) else { return LINUX_OK; };
        let driver = rec.bound_driver;
        rec.bound_driver = 0;
        driver
    };
    if driver != 0 { remove_probe(driver, dev); }
    LINUX_OK
}

pub(super) fn unbind_driver(driver: usize) {
    let mut devs = [0usize; MAX_BIND_BATCH];
    let mut n = 0usize;
    {
        let mut g = DEVICE_STATE.lock();
        for rec in g.iter_mut().flatten() {
            if n == MAX_BIND_BATCH { break; }
            if rec.bound_driver == driver {
                rec.bound_driver = 0;
                devs[n] = rec.ptr;
                n += 1;
            }
        }
    }
    for dev in devs.iter().take(n) { remove_probe(driver, *dev); }
}

fn bind_record(dev: usize, driver: usize) {
    let mut g = DEVICE_STATE.lock();
    if let Some(rec) = g.iter_mut().flatten().find(|r| r.ptr == dev) {
        rec.bound_driver = driver;
        rec.uevent_seq = rec.uevent_seq.saturating_add(1);
        // SAFETY: dev points at a registered Linux struct device.
        unsafe { (*(dev as *mut LinuxDevice)).driver = driver as *mut LinuxDeviceDriver; }
    }
}

fn driver_bus(driver: usize) -> usize {
    if driver == 0 { return 0; }
    // SAFETY: driver pointer came from driver_register.
    unsafe { (*(driver as *mut LinuxDeviceDriver)).bus as usize }
}

fn device_bus(dev: usize) -> usize {
    if dev == 0 { return 0; }
    // SAFETY: device pointer came from device_add.
    unsafe { (*(dev as *mut LinuxDevice)).bus as usize }
}

fn probe(driver: usize, dev: usize) -> i32 {
    if driver == 0 || dev == 0 { return -LINUX_EINVAL; }
    // SAFETY: driver/device pointers were registered by Linux KPI callers.
    unsafe {
        let drv = &mut *(driver as *mut LinuxDeviceDriver);
        if let Some(probe) = drv.probe { probe(dev as *mut LinuxDevice) } else { LINUX_OK }
    }
}

fn remove_probe(driver: usize, dev: usize) {
    if driver == 0 || dev == 0 { return; }
    // SAFETY: driver/device pointers were registered and bound previously.
    unsafe {
        let drv = &mut *(driver as *mut LinuxDeviceDriver);
        if let Some(remove) = drv.remove { let _ = remove(dev as *mut LinuxDevice); }
        (*(dev as *mut LinuxDevice)).driver = core::ptr::null_mut();
    }
}
