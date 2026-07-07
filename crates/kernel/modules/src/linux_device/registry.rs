use super::types::{
    LinuxDevice, LinuxDeviceDriver, LINUX_EBUSY, LINUX_EINVAL, LINUX_ENOMEM, LINUX_OK,
};
use sync::{Modules as ModulesLockClass, Spinlock};

const MAX_DEVICE_RECORDS: usize = 64;
const MAX_KOBJECT_RECORDS: usize = 64;
const MAX_CLASS_RECORDS: usize = 32;
const MAX_BUS_RECORDS: usize = 32;
const MAX_DRIVER_RECORDS: usize = 32;
const MAX_DEVICE_ATTRS: usize = 16;
const MAX_BIND_BATCH: usize = 32;

#[derive(Copy, Clone)]
struct PtrRecord { ptr: usize }

#[cfg(test)]
#[derive(Copy, Clone)]
pub(super) struct DeviceSnapshot {
    pub(super) class: usize,
    pub(super) devt: u32,
    pub(super) refs: usize,
    pub(super) attr_count: usize,
    pub(super) uevent_seq: u64,
    pub(super) bound_driver: usize,
}

#[derive(Copy, Clone)]
struct DeviceRecord {
    ptr: usize,
    refs: usize,
    added: bool,
    class: usize,
    devt: u32,
    owned: bool,
    bound_driver: usize,
    attrs: [usize; MAX_DEVICE_ATTRS],
    attr_count: usize,
    uevent_seq: u64,
}

#[derive(Copy, Clone)]
struct KobjectRecord {
    ptr: usize,
    refs: usize,
    attrs: [usize; MAX_DEVICE_ATTRS],
    attr_count: usize,
    uevent_seq: u64,
}

static DEVICES: Spinlock<[Option<PtrRecord>; MAX_DEVICE_RECORDS], ModulesLockClass> =
    Spinlock::new([None; MAX_DEVICE_RECORDS]);
static DEVICE_STATE: Spinlock<[Option<DeviceRecord>; MAX_DEVICE_RECORDS], ModulesLockClass> =
    Spinlock::new([None; MAX_DEVICE_RECORDS]);
static KOBJECT_STATE: Spinlock<[Option<KobjectRecord>; MAX_KOBJECT_RECORDS], ModulesLockClass> =
    Spinlock::new([None; MAX_KOBJECT_RECORDS]);
static CLASSES: Spinlock<[Option<PtrRecord>; MAX_CLASS_RECORDS], ModulesLockClass> =
    Spinlock::new([None; MAX_CLASS_RECORDS]);
static BUSES: Spinlock<[Option<PtrRecord>; MAX_BUS_RECORDS], ModulesLockClass> =
    Spinlock::new([None; MAX_BUS_RECORDS]);
static DRIVERS: Spinlock<[Option<PtrRecord>; MAX_DRIVER_RECORDS], ModulesLockClass> =
    Spinlock::new([None; MAX_DRIVER_RECORDS]);

pub(super) fn initialize_device(ptr: usize) {
    let mut g = DEVICE_STATE.lock();
    match g.iter_mut().find(|r| r.is_some_and(|v| v.ptr == ptr)) {
        Some(slot) => *slot = Some(DeviceRecord::new(ptr, false)),
        None => {
            if let Some(slot) = g.iter_mut().find(|r| r.is_none()) {
                *slot = Some(DeviceRecord::new(ptr, false));
            }
        }
    }
}

pub(super) fn add_device(ptr: usize, class: usize, devt: u32, owned: bool) -> i32 {
    {
        let mut g = DEVICE_STATE.lock();
        let slot = match g.iter_mut().find(|r| r.is_some_and(|v| v.ptr == ptr)) {
            Some(slot) => slot,
            None => match g.iter_mut().find(|r| r.is_none()) {
                Some(slot) => slot,
                None => return -LINUX_ENOMEM,
            },
        };
        if let Some(rec) = slot {
            if rec.added { return -LINUX_EBUSY; }
            rec.refs = rec.refs.max(1);
            rec.added = true;
            rec.class = class;
            rec.devt = devt;
            rec.owned = owned;
            rec.uevent_seq = rec.uevent_seq.saturating_add(1);
        } else {
            let mut rec = DeviceRecord::new(ptr, owned);
            rec.added = true;
            rec.class = class;
            rec.devt = devt;
            rec.uevent_seq = 1;
            *slot = Some(rec);
        }
    }
    let rc = bind_device(ptr);
    if rc == LINUX_OK { insert(&DEVICES, ptr) } else {
        let _ = unbind_device(ptr);
        let mut g = DEVICE_STATE.lock();
        if let Some(rec) = g.iter_mut().flatten().find(|r| r.ptr == ptr) {
            rec.added = false;
            rec.uevent_seq = rec.uevent_seq.saturating_add(1);
        }
        rc
    }
}

pub(super) fn remove_device(ptr: usize) {
    let _ = unbind_device(ptr);
    remove(&DEVICES, ptr);
    let mut g = DEVICE_STATE.lock();
    if let Some(rec) = g.iter_mut().flatten().find(|r| r.ptr == ptr) {
        rec.added = false;
        rec.class = 0;
        rec.devt = 0;
        rec.attrs = [0; MAX_DEVICE_ATTRS];
        rec.attr_count = 0;
        rec.uevent_seq = rec.uevent_seq.saturating_add(1);
    }
}

pub(super) fn get_device(ptr: usize) -> bool {
    let mut g = DEVICE_STATE.lock();
    if let Some(rec) = g.iter_mut().flatten().find(|r| r.ptr == ptr) {
        rec.refs = rec.refs.saturating_add(1);
        true
    } else { false }
}

pub(super) fn put_device(ptr: usize) -> Option<bool> {
    let mut g = DEVICE_STATE.lock();
    for slot in g.iter_mut() {
        if let Some(mut rec) = *slot {
            if rec.ptr != ptr { continue; }
            rec.refs = rec.refs.saturating_sub(1);
            if rec.refs == 0 {
                let owned = rec.owned;
                *slot = None;
                return Some(owned);
            }
            *slot = Some(rec);
            return None;
        }
    }
    Some(false)
}

pub(super) fn mark_owned(ptr: usize) {
    let mut g = DEVICE_STATE.lock();
    if let Some(rec) = g.iter_mut().flatten().find(|r| r.ptr == ptr) { rec.owned = true; }
}

pub(super) fn find_class_devt(class: usize, devt: u32) -> Option<usize> {
    let g = DEVICE_STATE.lock();
    g.iter().flatten().find(|r| r.added && r.class == class && r.devt == devt).map(|r| r.ptr)
}

pub(super) fn add_attr(dev: usize, attr: usize) -> i32 {
    if attr == 0 { return -LINUX_EINVAL; }
    let mut g = DEVICE_STATE.lock();
    let Some(rec) = g.iter_mut().flatten().find(|r| r.ptr == dev && r.added) else { return -LINUX_EINVAL; };
    if rec.attrs.iter().take(rec.attr_count).any(|v| *v == attr) { return -LINUX_EBUSY; }
    if rec.attr_count >= MAX_DEVICE_ATTRS { return -LINUX_ENOMEM; }
    rec.attrs[rec.attr_count] = attr;
    rec.attr_count += 1;
    rec.uevent_seq = rec.uevent_seq.saturating_add(1);
    LINUX_OK
}

pub(super) fn remove_attr(dev: usize, attr: usize) {
    let mut g = DEVICE_STATE.lock();
    let Some(rec) = g.iter_mut().flatten().find(|r| r.ptr == dev) else { return; };
    if let Some(pos) = rec.attrs.iter().take(rec.attr_count).position(|v| *v == attr) {
        for i in pos..rec.attr_count - 1 { rec.attrs[i] = rec.attrs[i + 1]; }
        rec.attr_count -= 1;
        rec.attrs[rec.attr_count] = 0;
        rec.uevent_seq = rec.uevent_seq.saturating_add(1);
    }
}

#[cfg(test)]
pub(super) fn snapshot(dev: usize) -> Option<DeviceSnapshot> {
    let g = DEVICE_STATE.lock();
    g.iter().flatten().find(|r| r.ptr == dev).map(|r| DeviceSnapshot {
        class: r.class, devt: r.devt, refs: r.refs, attr_count: r.attr_count,
        uevent_seq: r.uevent_seq, bound_driver: r.bound_driver,
    })
}

pub(super) fn initialize_kobject(ptr: usize) {
    let mut g = KOBJECT_STATE.lock();
    match g.iter_mut().find(|r| r.is_some_and(|v| v.ptr == ptr)) {
        Some(slot) => *slot = Some(KobjectRecord::new(ptr)),
        None => {
            if let Some(slot) = g.iter_mut().find(|r| r.is_none()) { *slot = Some(KobjectRecord::new(ptr)); }
        }
    }
}

pub(super) fn get_kobject(ptr: usize) {
    let mut g = KOBJECT_STATE.lock();
    if let Some(rec) = g.iter_mut().flatten().find(|r| r.ptr == ptr) {
        rec.refs = rec.refs.saturating_add(1);
    }
}

pub(super) fn remove_kobject(ptr: usize) {
    let mut g = KOBJECT_STATE.lock();
    if let Some(slot) = g.iter_mut().find(|r| r.is_some_and(|v| v.ptr == ptr)) { *slot = None; }
}

pub(super) fn add_kobject_attr(kobj: usize, attr: usize) -> i32 {
    if attr == 0 { return -LINUX_EINVAL; }
    let mut g = KOBJECT_STATE.lock();
    let Some(rec) = g.iter_mut().flatten().find(|r| r.ptr == kobj) else { return -LINUX_EINVAL; };
    if rec.attrs.iter().take(rec.attr_count).any(|v| *v == attr) { return -LINUX_EBUSY; }
    if rec.attr_count >= MAX_DEVICE_ATTRS { return -LINUX_ENOMEM; }
    rec.attrs[rec.attr_count] = attr;
    rec.attr_count += 1;
    rec.uevent_seq = rec.uevent_seq.saturating_add(1);
    LINUX_OK
}

pub(super) fn remove_kobject_attr(kobj: usize, attr: usize) {
    let mut g = KOBJECT_STATE.lock();
    let Some(rec) = g.iter_mut().flatten().find(|r| r.ptr == kobj) else { return; };
    if let Some(pos) = rec.attrs.iter().take(rec.attr_count).position(|v| *v == attr) {
        for i in pos..rec.attr_count - 1 { rec.attrs[i] = rec.attrs[i + 1]; }
        rec.attr_count -= 1;
        rec.attrs[rec.attr_count] = 0;
        rec.uevent_seq = rec.uevent_seq.saturating_add(1);
    }
}

pub(super) fn record_kobject_uevent(kobj: usize) {
    let mut g = KOBJECT_STATE.lock();
    if let Some(rec) = g.iter_mut().flatten().find(|r| r.ptr == kobj) {
        rec.uevent_seq = rec.uevent_seq.saturating_add(1);
    }
}

#[cfg(test)]
pub(super) fn kobject_attr_count(kobj: usize) -> usize {
    let g = KOBJECT_STATE.lock();
    g.iter().flatten().find(|r| r.ptr == kobj).map_or(0, |r| r.attr_count)
}

pub(super) fn insert_class(ptr: usize) -> i32 { insert(&CLASSES, ptr) }
pub(super) fn remove_class(ptr: usize) { remove(&CLASSES, ptr); }
pub(super) fn insert_bus(ptr: usize) -> i32 { insert(&BUSES, ptr) }
pub(super) fn remove_bus(ptr: usize) { remove(&BUSES, ptr); }
pub(super) fn insert_driver(ptr: usize) -> i32 {
    let rc = insert(&DRIVERS, ptr);
    if rc != LINUX_OK { return rc; }
    let rc = bind_driver(ptr);
    if rc != LINUX_OK { remove(&DRIVERS, ptr); }
    rc
}
pub(super) fn remove_driver(ptr: usize) {
    unbind_driver(ptr);
    remove(&DRIVERS, ptr);
}

impl DeviceRecord {
    fn new(ptr: usize, owned: bool) -> Self {
        Self {
            ptr, refs: 1, added: false, class: 0, devt: 0, owned, bound_driver: 0,
            attrs: [0; MAX_DEVICE_ATTRS], attr_count: 0, uevent_seq: 0,
        }
    }
}

impl KobjectRecord {
    fn new(ptr: usize) -> Self {
        Self { ptr, refs: 1, attrs: [0; MAX_DEVICE_ATTRS], attr_count: 0, uevent_seq: 0 }
    }
}

fn bind_driver(driver: usize) -> i32 {
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

fn bind_device(dev: usize) -> i32 {
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

fn unbind_device(dev: usize) -> i32 {
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

fn unbind_driver(driver: usize) {
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

fn insert<const N: usize>(
    table: &Spinlock<[Option<PtrRecord>; N], ModulesLockClass>,
    ptr: usize,
) -> i32 {
    let mut g = table.lock();
    if g.iter().flatten().any(|r| r.ptr == ptr) { return -LINUX_EBUSY; }
    if let Some(slot) = g.iter_mut().find(|r| r.is_none()) {
        *slot = Some(PtrRecord { ptr });
        LINUX_OK
    } else { -LINUX_ENOMEM }
}

fn remove<const N: usize>(table: &Spinlock<[Option<PtrRecord>; N], ModulesLockClass>, ptr: usize) {
    let mut g = table.lock();
    if let Some(slot) = g.iter_mut().find(|r| r.is_some_and(|v| v.ptr == ptr)) { *slot = None; }
}
