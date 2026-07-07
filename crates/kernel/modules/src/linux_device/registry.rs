use super::types::{LINUX_EBUSY, LINUX_ENOMEM, LINUX_OK};
use sync::{Modules as ModulesLockClass, Spinlock};

const MAX_DEVICE_RECORDS: usize = 64;
const MAX_CLASS_RECORDS: usize = 32;
const MAX_BUS_RECORDS: usize = 32;
const MAX_DRIVER_RECORDS: usize = 32;

#[derive(Copy, Clone)]
struct PtrRecord { ptr: usize }

static DEVICES: Spinlock<[Option<PtrRecord>; MAX_DEVICE_RECORDS], ModulesLockClass> =
    Spinlock::new([None; MAX_DEVICE_RECORDS]);
static CLASSES: Spinlock<[Option<PtrRecord>; MAX_CLASS_RECORDS], ModulesLockClass> =
    Spinlock::new([None; MAX_CLASS_RECORDS]);
static BUSES: Spinlock<[Option<PtrRecord>; MAX_BUS_RECORDS], ModulesLockClass> =
    Spinlock::new([None; MAX_BUS_RECORDS]);
static DRIVERS: Spinlock<[Option<PtrRecord>; MAX_DRIVER_RECORDS], ModulesLockClass> =
    Spinlock::new([None; MAX_DRIVER_RECORDS]);

pub(super) fn insert_device(ptr: usize) -> i32 { insert(&DEVICES, ptr) }
pub(super) fn remove_device(ptr: usize) { remove(&DEVICES, ptr); }
pub(super) fn insert_class(ptr: usize) -> i32 { insert(&CLASSES, ptr) }
pub(super) fn remove_class(ptr: usize) { remove(&CLASSES, ptr); }
pub(super) fn insert_bus(ptr: usize) -> i32 { insert(&BUSES, ptr) }
pub(super) fn remove_bus(ptr: usize) { remove(&BUSES, ptr); }
pub(super) fn insert_driver(ptr: usize) -> i32 { insert(&DRIVERS, ptr) }
pub(super) fn remove_driver(ptr: usize) { remove(&DRIVERS, ptr); }

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
