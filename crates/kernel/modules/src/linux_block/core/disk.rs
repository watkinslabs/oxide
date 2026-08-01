extern crate alloc;
use super::adapter::LinuxBlockAdapter;
use crate::linux_block::contract::release_needs_unregister;
use crate::linux_block::types::*;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use block::BlockDevice;
use core::ffi::c_char;
use core::ptr::null_mut;

pub(super) const DEFAULT_MINORS: i32 = 1;
const DEFAULT_NODE_ID: i32 = 0;
const DISK_DEAD_FLAG: u32 = 1 << 31;
const REGISTERED_NO: u32 = 0;
const REGISTERED_YES: u32 = 1;

/// Register the gendisk half of the block KPI.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    export("alloc_disk",      alloc_disk      as *const () as usize, false);
    export("alloc_disk_node", alloc_disk_node as *const () as usize, false);
    export("put_disk",        put_disk        as *const () as usize, false);
    export("add_disk",        add_disk        as *const () as usize, false);
    export("del_gendisk",     del_gendisk     as *const () as usize, false);
    export("set_capacity",    set_capacity    as *const () as usize, false);
    export("get_capacity",    get_capacity    as *const () as usize, false);
}

pub(super) extern "C" fn alloc_disk(minors: i32) -> *mut LinuxGendisk {
    alloc_disk_node(minors, DEFAULT_NODE_ID)
}

pub(in crate::linux_block) extern "C" fn alloc_disk_node(minors: i32, _node_id: i32) -> *mut LinuxGendisk {
    let dev = {
        // SAFETY: LinuxDevice is a C POD mirror; zero initialization matches kzalloc.
        unsafe { core::mem::zeroed() }
    };
    Box::into_raw(Box::new(LinuxGendisk {
        major: 0,
        first_minor: 0,
        minors: if minors <= 0 { DEFAULT_MINORS } else { minors },
        disk_name: [0; DISK_NAME_LEN],
        fops: core::ptr::null(),
        queue: null_mut(),
        private_data: null_mut(),
        capacity: 0,
        flags: 0,
        dev,
        registered: REGISTERED_NO,
    }))
}

/// Release a gendisk, withdrawing any block-registry publication it still holds first.
/// # C: O(name length)
pub(in crate::linux_block) unsafe extern "C" fn put_disk(disk: *mut LinuxGendisk) {
    if disk.is_null() { return; }
    // The registry holds an adapter that dereferences this same gendisk from safe code, so a publication
    // the module never withdrew (put_disk without del_gendisk) must be withdrawn before the Box below
    // frees the allocation; release_needs_unregister decides that from the publication flag alone.
    // SAFETY: disk is null-checked and, per the put_disk KPI, is the module's gendisk from alloc_disk*,
    // so `registered` and disk_name are readable fields of that still-live allocation.
    unsafe {
        let name = disk_name(disk);
        if release_needs_unregister((*disk).registered, name.len()) { del_gendisk(disk); }
    }
    // SAFETY: disk was allocated by alloc_disk* and, after the unregister above, the block registry no
    // longer holds an adapter naming it, so this Box::from_raw is the last reference to the allocation.
    unsafe { drop(Box::from_raw(disk)); }
}

pub(in crate::linux_block) unsafe extern "C" fn add_disk(disk: *mut LinuxGendisk) {
    if disk.is_null() { return; }
    // SAFETY: disk is null-checked above and, per the add_disk KPI, is a gendisk the module obtained from
    // alloc_disk/alloc_disk_node and has not yet passed to put_disk, so its disk_name array is initialised.
    let name = unsafe { disk_name(disk) };
    if name.is_empty() { return; }
    let adapter = Arc::new(LinuxBlockAdapter::new(disk)) as Arc<dyn BlockDevice>;
    let idx = block::registry::register_with_driver(
        block::registry::GENERIC_BLOCK_DRIVER, &name, None, adapter);
    // SAFETY: same null-checked gendisk allocation as above; registered/queue are plain fields of it. The
    // queue back-pointer store is guarded by the is_null test, and (*disk).queue is either null or the
    // blk_alloc_queue Box the module attached, whose `disk` field is likewise plain data.
    unsafe {
        (*disk).registered = if idx == 0 { REGISTERED_NO } else { REGISTERED_YES };
        if !(*disk).queue.is_null() { (*(*disk).queue).disk = disk; }
    }
}

unsafe extern "C" fn del_gendisk(disk: *mut LinuxGendisk) {
    if disk.is_null() { return; }
    // SAFETY: disk is null-checked, and del_gendisk's KPI contract is that it runs before put_disk, so the
    // alloc_disk allocation and its disk_name array are still live here.
    let name = unsafe { disk_name(disk) };
    if !name.is_empty() { let _ = block::registry::unregister(&name); }
    // SAFETY: same live gendisk; clearing `registered` must happen after the registry drops its adapter so
    // the flag never claims a publication the block registry no longer has.
    unsafe { (*disk).registered = REGISTERED_NO; }
}

unsafe extern "C" fn set_capacity(disk: *mut LinuxGendisk, sectors: u64) {
    if disk.is_null() { return; }
    // SAFETY: disk is null-checked and owned by the calling module between alloc_disk and put_disk; capacity
    // is a u64 field of that allocation, read back only through get_capacity/capacity_blocks.
    unsafe { (*disk).capacity = sectors; }
}

unsafe extern "C" fn get_capacity(disk: *const LinuxGendisk) -> u64 {
    if disk.is_null() { return 0; }
    // SAFETY: disk is null-checked; alloc_disk_node zero-initialises capacity before publishing the gendisk,
    // so this load is defined even if the module never called set_capacity.
    unsafe { (*disk).capacity }
}

/// Mark a gendisk dead so its holders stop issuing new I/O.
/// # C: O(1)
pub(in crate::linux_block) unsafe fn mark_disk_dead(disk: *mut LinuxGendisk) {
    if disk.is_null() { return; }
    // SAFETY: disk is null-checked and, per the blk_mark_disk_dead KPI, is the module's gendisk from
    // alloc_disk*; `flags` is a u32 field of that allocation, so the read-modify-write stays in bounds.
    unsafe { (*disk).flags |= DISK_DEAD_FLAG; }
}

pub(super) fn sectors_to_blocks(sectors: u64, block_size: u32) -> u64 {
    let factor = (block_size / LINUX_SECTOR_SIZE).max(1) as u64;
    sectors / factor
}

pub(super) fn blocks_to_sectors(blocks: u64, block_size: u32) -> u64 {
    let factor = (block_size / LINUX_SECTOR_SIZE).max(1) as u64;
    blocks.saturating_mul(factor)
}

// Precondition: disk is null or points to a live LinuxGendisk allocation (alloc_disk_node, not yet put_disk).
unsafe fn disk_name(disk: *const LinuxGendisk) -> String {
    if disk.is_null() { return String::new(); }
    let mut out = String::new();
    // SAFETY: disk_name is a `[c_char; DISK_NAME_LEN]` inline array of the live gendisk, so iterating it by
    // reference stays in bounds regardless of whether a NUL terminator is present; the break only shortens
    // the walk, it is not what keeps it in bounds.
    unsafe {
        for c in &(*disk).disk_name {
            if *c == c_char::default() { break; }
            out.push((*c as u8) as char);
        }
    }
    out
}

#[cfg(test)]
pub(super) fn write_disk_name(disk: *mut LinuxGendisk, name: &[u8]) {
    if disk.is_null() { return; }
    // SAFETY: disk points to a fixed-size C name field owned by the test.
    unsafe {
        (*disk).disk_name = [0; DISK_NAME_LEN];
        let n = name.len().min(DISK_NAME_LEN - 1);
        for (dst, src) in (*disk).disk_name.iter_mut().take(n).zip(name.iter().copied()) {
            *dst = src as c_char;
        }
    }
}
