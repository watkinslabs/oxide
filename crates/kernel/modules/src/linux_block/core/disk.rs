extern crate alloc;
use super::adapter::LinuxBlockAdapter;
use crate::linux_block::contract::release_needs_unregister;
use crate::linux_device::types::{LinuxKobject, LinuxKset};
use crate::linux_block::types::*;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use block::BlockDevice;
use core::ffi::c_char;
use core::ptr::null_mut;
use sync::{Modules as ModulesLockClass, Spinlock};

pub(super) const DEFAULT_MINORS: i32 = 1;
const DEFAULT_NODE_ID: i32 = 0;
pub(super) const GENHD_FL_HIDDEN: u32 = 1 << 1;
pub(super) const GD_READ_ONLY: usize = 1 << 1;
const GD_DEAD: usize = 1 << 2;
const GD_ADDED: usize = 1 << 4;
static BLOCK_KSET: Spinlock<usize, ModulesLockClass> = Spinlock::new(0);

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
    export("set_capacity_and_notify", set_capacity_and_notify as *const () as usize, true);
    export("set_disk_ro", set_disk_ro as *const () as usize, false);
    export("disk_uevent", disk_uevent as *const () as usize, true);
    export("get_capacity",    get_capacity    as *const () as usize, false);
    export("disk_live",       disk_live       as *const () as usize, false);
}

pub(super) extern "C" fn alloc_disk(minors: i32) -> *mut LinuxGendisk {
    alloc_disk_node(minors, DEFAULT_NODE_ID)
}

pub(in crate::linux_block) extern "C" fn alloc_disk_node(minors: i32, _node_id: i32) -> *mut LinuxGendisk {
    let mut part0 = Box::new(LinuxBlockDevice::new());
    let disk = Box::new(LinuxGendisk {
        major: 0,
        first_minor: 0,
        minors: if minors <= 0 { DEFAULT_MINORS } else { minors },
        disk_name: [0; DISK_NAME_LEN],
        events: 0, event_flags: 0, part_tbl: [0; 16], part0: null_mut(), fops: core::ptr::null(),
        queue: null_mut(),
        private_data: null_mut(),
        bio_split: null_mut(), _pre_flags: [0; 240], flags: 0, _state_pad: 0, state: 0,
        open_mutex: [0; 32], open_partitions: 0, _bdi_pad: 0, bdi: null_mut(),
        queue_kobj: LinuxKobject { name: null_mut(), entry: [null_mut(); 2], parent: null_mut(),
            kset: null_mut(), ktype: core::ptr::null(), sd: null_mut(), kref: 1, state: 0 },
        slave_dir: null_mut(), slave_bdevs: [0; 16], random: null_mut(), ev: null_mut(), _zoned: [0; 72],
        node_id: _node_id, _node_pad: 0, bb: null_mut(), diskseq: 0, open_mode: 0, _open_mode_pad: 0,
        ia_ranges: null_mut(), rqos_state_mutex: [0; 32],
    });
    let disk = Box::into_raw(disk);
    part0.bd_disk = disk;
    // SAFETY: disk is the fresh allocation above and part0 is heap-owned until put_disk releases it.
    unsafe { (*disk).part0 = Box::into_raw(part0); }
    disk
}

/// Release a gendisk, withdrawing any block-registry publication it still holds first.
/// # C: O(name length)
pub(in crate::linux_block) unsafe extern "C" fn put_disk(disk: *mut LinuxGendisk) {
    if disk.is_null() { return; }
    // The registry holds an adapter that dereferences this same gendisk from safe code, so a publication
    // the module never withdrew (put_disk without del_gendisk) must be withdrawn before the Box below
    // frees the allocation; release_needs_unregister decides that from the added state alone.
    // SAFETY: disk is null-checked and, per the put_disk KPI, is the module's gendisk from alloc_disk*,
    // so `state` and disk_name are readable fields of that still-live allocation.
    unsafe {
        let name = disk_name(disk);
        if release_needs_unregister((*disk).state & GD_ADDED != 0, name.len()) { del_gendisk(disk); }
    }
    // SAFETY: disk was allocated by alloc_disk* and, after the unregister above, the block registry no
    // longer holds an adapter naming it, so this Box::from_raw is the last reference to the allocation.
    // SAFETY: the part-zero device has been withdrawn above (if published), and its kobject record must end
    // before its owning block-device allocation and containing gendisk are reclaimed.
    unsafe {
        if !(*disk).part0.is_null() {
            crate::linux_device::core::release_embedded(&mut (*(*disk).part0).bd_device);
            drop(Box::from_raw((*disk).part0));
        }
        drop(Box::from_raw(disk));
    }
}

pub(in crate::linux_block) unsafe extern "C" fn add_disk(disk: *mut LinuxGendisk) {
    if disk.is_null() { return; }
    // SAFETY: disk is null-checked above and, per the add_disk KPI, is a gendisk the module obtained from
    // alloc_disk/alloc_disk_node and has not yet passed to put_disk, so its disk_name array is initialised.
    let name = unsafe { disk_name(disk) };
    if name.is_empty() { return; }
    // SAFETY: part zero belongs to this live gendisk; its NUL-terminated disk name is the device identity,
    // so device-core publication precedes the block adapter that makes it externally reachable.
    unsafe {
        if (*disk).part0.is_null() { return; }
        let dev = &mut (*(*disk).part0).bd_device;
        crate::linux_device::core::initialize_embedded(dev);
        dev.kobj.kset = block_kset();
        crate::linux_device::core::set_name_from_cstr(dev, (*disk).disk_name.as_ptr());
        if crate::linux_device::core::device_add(dev) != LINUX_OK { return; }
    }
    let adapter = Arc::new(LinuxBlockAdapter::new(disk)) as Arc<dyn BlockDevice>;
    let idx = block::registry::register_with_driver(
        block::registry::GENERIC_BLOCK_DRIVER, &name, None, adapter);
    // SAFETY: same null-checked gendisk allocation as above; state/queue are plain fields of it. The
    // queue back-pointer store is guarded by the is_null test, and (*disk).queue is either null or the
    // blk_alloc_queue Box the module attached, whose `disk` field is likewise plain data.
    unsafe {
        if idx == 0 { (*disk).state &= !GD_ADDED; } else { (*disk).state |= GD_ADDED; }
        if !(*disk).queue.is_null() { (*(*disk).queue).disk = disk; }
    }
}

fn block_kset() -> *mut LinuxKset {
    let mut slot = BLOCK_KSET.lock();
    if *slot == 0 {
        let kset = Box::new(LinuxKset {
            list: [null_mut(); 2], list_lock: 0, _pad: 0,
            kobj: LinuxKobject { name: c"block".as_ptr(), entry: [null_mut(); 2], parent: null_mut(),
                kset: null_mut(), ktype: core::ptr::null(), sd: null_mut(), kref: 1, state: 1 },
            uevent_ops: core::ptr::null(),
        });
        *slot = Box::into_raw(kset) as usize;
    }
    *slot as *mut LinuxKset
}

unsafe extern "C" fn del_gendisk(disk: *mut LinuxGendisk) {
    if disk.is_null() { return; }
    // SAFETY: disk is null-checked, and del_gendisk's KPI contract is that it runs before put_disk, so the
    // alloc_disk allocation and its disk_name array are still live here.
    let name = unsafe { disk_name(disk) };
    if !name.is_empty() { let _ = block::registry::unregister(&name); }
    // SAFETY: same live gendisk; clearing added state must happen after the registry drops its adapter so
    // the state bit never claims a publication the block registry no longer has.
    unsafe {
        (*disk).state &= !GD_ADDED;
        if !(*disk).part0.is_null() { crate::linux_device::core::device_del(&mut (*(*disk).part0).bd_device); }
    }
}

/// Store a gendisk sector count without sending a device event.
/// # C: O(1)
pub(super) unsafe extern "C" fn set_capacity(disk: *mut LinuxGendisk, sectors: u64) {
    if disk.is_null() { return; }
    // SAFETY: disk is null-checked and owned by the calling module between alloc_disk and put_disk; capacity
    // is a u64 field of that allocation, read back only through get_capacity/capacity_blocks.
    unsafe { if !(*disk).part0.is_null() { (*(*disk).part0).bd_nr_sectors = sectors; } }
}

/// Store capacity and announce a visible nonempty live resize.
/// # C: O(name depth)
pub(super) unsafe extern "C" fn set_capacity_and_notify(disk: *mut LinuxGendisk, sectors: u64) -> bool {
    if disk.is_null() { return false; }
    // SAFETY: disk is null-checked and remains the caller-owned gendisk throughout this capacity transition.
    let previous = unsafe { if (*disk).part0.is_null() { 0 } else { (*(*disk).part0).bd_nr_sectors } };
    // SAFETY: same live gendisk; setting capacity precedes every visibility decision just as it does for all callers.
    unsafe { set_capacity(disk, sectors); }
    // SAFETY: same live gendisk; liveness and flags are its canonical publication state and visibility flags.
    if sectors == previous || !unsafe { disk_live(disk) } || unsafe { (*disk).flags & GENHD_FL_HIDDEN != 0 } { return false; }
    if previous == 0 || sectors == 0 { return false; }
    let mut envp = [c"RESIZE=1".as_ptr() as *mut c_char, null_mut()];
    // SAFETY: the disk is live and its part-zero device was initialized and published before the block registry.
    unsafe { if !(*disk).part0.is_null() { crate::linux_device::core::device_change_uevent(&mut (*(*disk).part0).bd_device, envp.as_mut_ptr()); } }
    true
}

/// Toggle the gendisk read-only state and report state changes to user space.
/// # C: O(name depth)
pub(super) unsafe extern "C" fn set_disk_ro(disk: *mut LinuxGendisk, read_only: bool) {
    if disk.is_null() { return; }
    // SAFETY: disk is null-checked and remains caller-owned while its state word is updated.
    let was_read_only = unsafe { (*disk).state & GD_READ_ONLY != 0 };
    if was_read_only == read_only { return; }
    // SAFETY: same live gendisk state word; this is the single gendisk read-only owner.
    unsafe {
        if read_only { (*disk).state |= GD_READ_ONLY; } else { (*disk).state &= !GD_READ_ONLY; }
    }
    let event = if read_only { c"DISK_RO=1" } else { c"DISK_RO=0" };
    let mut envp = [event.as_ptr() as *mut c_char, null_mut()];
    // SAFETY: same disk; event vector is local and NULL-terminated for the duration of the synchronous call.
    unsafe { if !(*disk).part0.is_null() { crate::linux_device::core::device_change_uevent(&mut (*(*disk).part0).bd_device, envp.as_mut_ptr()); } }
}

/// Forward a disk event to every present block-device object this gendisk owns.
/// # C: O(name depth)
pub(super) unsafe extern "C" fn disk_uevent(disk: *mut LinuxGendisk, action: u32) {
    if disk.is_null() { return; }
    // SAFETY: disk is null-checked and its part-zero device remains live for this synchronous event call.
    unsafe { if !(*disk).part0.is_null() { crate::linux_device::core::device_uevent(&mut (*(*disk).part0).bd_device, action); } }
}

unsafe extern "C" fn get_capacity(disk: *const LinuxGendisk) -> u64 {
    if disk.is_null() { return 0; }
    // SAFETY: disk is null-checked; alloc_disk_node supplies a zeroed part-zero sector count before publication,
    // so this load is defined even if the module never called set_capacity.
    unsafe { if (*disk).part0.is_null() { 0 } else { (*(*disk).part0).bd_nr_sectors } }
}

/// Report whether the disk remains published and has not been withdrawn as dead.
/// # C: O(1)
pub(super) unsafe extern "C" fn disk_live(disk: *mut LinuxGendisk) -> bool {
    if disk.is_null() { return false; }
    // SAFETY: disk is caller-owned live gendisk storage; the registry publication flag and dead bit are
    // the canonical Oxide counterparts to the live part-0 backing object tested by block paths.
    unsafe { (*disk).state & (GD_ADDED | GD_DEAD) == GD_ADDED }
}

/// Mark a gendisk dead so its holders stop issuing new I/O.
/// # C: O(1)
pub(in crate::linux_block) unsafe fn mark_disk_dead(disk: *mut LinuxGendisk) {
    if disk.is_null() { return; }
    // SAFETY: disk is null-checked and, per the blk_mark_disk_dead KPI, is the module's gendisk from
    // alloc_disk*; `state` is the gendisk lifecycle word, so the read-modify-write stays in bounds.
    unsafe { (*disk).state |= GD_DEAD; }
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
