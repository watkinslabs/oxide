use super::types::{DevresAction, LinuxDevice, LINUX_EINVAL, LINUX_ENOMEM, LINUX_OK};
use alloc::alloc::{alloc, dealloc, Layout};
use core::ffi::c_void;
use core::mem::{align_of, size_of};
use core::ptr::{null_mut, write_bytes};
use sync::{Modules as ModulesLockClass, Spinlock};

const MAX_DEVRES_RECORDS: usize = 128;
const DEVRES_MAGIC: u64 = 0x4f58_4b50_4452_4553;
const MIN_ALIGN: usize = align_of::<usize>();

#[repr(C)]
#[derive(Copy, Clone)]
struct DevresHeader {
    magic: u64,
    total: usize,
    align: usize,
    off: usize,
}

#[derive(Copy, Clone)]
struct DevresRecord {
    dev: usize,
    ptr: usize,
    action: usize,
    data: usize,
}

static DEVRES: Spinlock<[Option<DevresRecord>; MAX_DEVRES_RECORDS], ModulesLockClass> =
    Spinlock::new([None; MAX_DEVRES_RECORDS]);

pub(super) fn alloc_devres(dev: *mut LinuxDevice, size: usize, zero: bool) -> *mut c_void {
    if dev.is_null() || size == 0 { return null_mut(); }
    let ptr = alloc_bytes(size, MIN_ALIGN, zero);
    if ptr.is_null() { return null_mut(); }
    let rec = DevresRecord { dev: dev as usize, ptr: ptr as usize, action: 0, data: 0 };
    if insert(rec).is_err() {
        free_devres(ptr);
        return null_mut();
    }
    ptr
}

pub(super) fn free_devres_for(dev: *mut LinuxDevice, ptr: *mut c_void) {
    if dev.is_null() || ptr.is_null() { return; }
    if remove_ptr(dev as usize, ptr as usize).is_some() { free_devres(ptr); }
}

pub(super) fn add_action_or_reset(
    dev: *mut LinuxDevice,
    action: Option<DevresAction>,
    data: *mut c_void,
) -> i32 {
    let action = match action { Some(v) => v, None => return -LINUX_EINVAL };
    if dev.is_null() { return -LINUX_EINVAL; }
    let rec = DevresRecord { dev: dev as usize, ptr: 0, action: action as usize, data: data as usize };
    if insert(rec).is_ok() { LINUX_OK } else {
        // SAFETY: Linux devm_add_action_or_reset runs the supplied action on add failure.
        unsafe { action(data); }
        -LINUX_ENOMEM
    }
}

pub(super) fn remove_action(dev: *mut LinuxDevice, action: Option<DevresAction>, data: *mut c_void) {
    let action = match action { Some(v) => v, None => return };
    if dev.is_null() { return; }
    let mut g = DEVRES.lock();
    if let Some(slot) = g.iter_mut().find(|r| {
        r.is_some_and(|v| v.dev == dev as usize && v.action == action as usize && v.data == data as usize)
    }) { *slot = None; }
}

pub(super) fn release_device(dev: *mut LinuxDevice) {
    let mut records = [None; MAX_DEVRES_RECORDS];
    let mut n = 0usize;
    {
        let mut g = DEVRES.lock();
        for slot in g.iter_mut() {
            if let Some(rec) = *slot {
                if rec.dev == dev as usize {
                    records[n] = Some(rec);
                    n += 1;
                    *slot = None;
                }
            }
        }
    }
    for rec in records.iter().take(n).flatten() {
        if rec.ptr != 0 { free_devres(rec.ptr as *mut c_void); }
        if rec.action != 0 {
            // SAFETY: action was installed by devm_add_action_or_reset with DevresAction ABI.
            let action: DevresAction = unsafe { core::mem::transmute(rec.action) };
            // SAFETY: Linux devres action owns its data argument contract.
            unsafe { action(rec.data as *mut c_void); }
        }
    }
}

fn alloc_bytes(size: usize, align: usize, zero: bool) -> *mut c_void {
    let align = align.max(MIN_ALIGN).next_power_of_two();
    let off = align_up(size_of::<DevresHeader>(), align);
    let total = match off.checked_add(size) { Some(v) => v, None => return null_mut() };
    let layout = match Layout::from_size_align(total, align.max(align_of::<DevresHeader>())) {
        Ok(v) => v,
        Err(_) => return null_mut(),
    };
    // SAFETY: alloc's non-zero-size precondition holds because off is align_up(size_of::<DevresHeader>(), align) so total >= size_of::<DevresHeader>() > 0; Layout::from_size_align already rejected any overflowing or misaligned combination.
    let base = unsafe { alloc(layout) };
    if base.is_null() { return null_mut(); }
    // SAFETY: base covers total bytes, off is within allocation.
    let user = unsafe { base.add(off) };
    let h = DevresHeader { magic: DEVRES_MAGIC, total, align: layout.align(), off };
    // SAFETY: header slot is immediately before user within allocation.
    unsafe {
        (user.sub(size_of::<DevresHeader>()) as *mut DevresHeader).write(h);
        if zero { write_bytes(user, 0, size); }
    }
    user as *mut c_void
}

fn free_devres(ptr: *mut c_void) {
    if ptr.is_null() { return; }
    let ptr = ptr as *mut u8;
    // SAFETY: ptr is expected to come from alloc_bytes.
    let h = unsafe { *(ptr.sub(size_of::<DevresHeader>()) as *const DevresHeader) };
    if h.magic != DEVRES_MAGIC { return; }
    let layout = match Layout::from_size_align(h.total, h.align) {
        Ok(v) => v,
        Err(_) => return,
    };
    // SAFETY: base/layout reconstruct the allocation made by alloc_bytes.
    unsafe { dealloc(ptr.sub(h.off), layout); }
}

fn insert(rec: DevresRecord) -> Result<(), ()> {
    let mut g = DEVRES.lock();
    if let Some(slot) = g.iter_mut().find(|r| r.is_none()) {
        *slot = Some(rec);
        Ok(())
    } else { Err(()) }
}

fn remove_ptr(dev: usize, ptr: usize) -> Option<DevresRecord> {
    let mut g = DEVRES.lock();
    for slot in g.iter_mut() {
        if slot.is_some_and(|r| r.dev == dev && r.ptr == ptr) { return slot.take(); }
    }
    None
}

fn align_up(v: usize, a: usize) -> usize {
    (v + (a - 1)) & !(a - 1)
}
