// Module manifest: Linux XArray tagged radix-tree ABI and operations.

extern crate alloc;

use alloc::boxed::Box;
use core::{ffi::c_void, ptr};
use crate::linux_sync::{spin_lock, spin_unlock, LinuxSpinlock};

const CHUNK_SHIFT: u8 = 6;
const CHUNK_SIZE: usize = 1 << CHUNK_SHIFT;
const NODE_TAG: usize = 2;
const NODE_MASK: usize = 3;
const LINUX_EEXIST: i32 = 17;
const LINUX_EINVAL: i32 = 22;
const LINUX_ERR_PTR_RANGE: usize = 4095;

#[repr(C)]
pub struct LinuxXArray { pub(crate) lock: LinuxSpinlock, pub(crate) flags: u32, pub(crate) head: *mut c_void }

struct XaNode { shift: u8, slots: [*mut c_void; CHUNK_SIZE] }

/// Register the XArray ABI used by loadable Linux drivers.
/// # C: O(1)
pub fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("xa_init_flags", xa_init_flags as *const () as usize),
        ("xa_load", xa_load as *const () as usize),
        ("xa_insert", xa_insert as *const () as usize),
        ("xa_store", xa_store as *const () as usize),
        ("xa_erase", xa_erase as *const () as usize),
        ("xa_find", xa_find as *const () as usize),
        ("xa_find_after", xa_find_after as *const () as usize),
        ("xa_destroy", xa_destroy as *const () as usize),
    ] { export(name, addr, false); }
}

pub(crate) extern "C" fn xa_init_flags(xa: *mut LinuxXArray, flags: u32) {
    if xa.is_null() { return; }
    // SAFETY: xa names caller-owned xarray storage.
    unsafe { ptr::write(xa, LinuxXArray { lock: LinuxSpinlock { state: 0 }, flags, head: ptr::null_mut() }); }
}

extern "C" fn xa_load(xa: *mut LinuxXArray, index: usize) -> *mut c_void {
    if xa.is_null() { return ptr::null_mut(); }
    with_lock(xa, |xa| load_locked(xa, index))
}

extern "C" fn xa_insert(xa: *mut LinuxXArray, index: usize, entry: *mut c_void, _gfp: u32) -> i32 {
    if xa.is_null() || entry.is_null() || invalid_entry(entry) { return -LINUX_EINVAL; }
    with_lock(xa, |xa| if load_locked(xa, index).is_null() { store_locked(xa, index, entry); 0 } else { -LINUX_EEXIST })
}

extern "C" fn xa_store(xa: *mut LinuxXArray, index: usize, entry: *mut c_void, _gfp: u32) -> *mut c_void {
    if xa.is_null() || invalid_entry(entry) { return err_ptr(LINUX_EINVAL); }
    with_lock(xa, |xa| { let old = load_locked(xa, index); if entry.is_null() { erase_locked(xa, index); } else { store_locked(xa, index, entry); } old })
}

extern "C" fn xa_erase(xa: *mut LinuxXArray, index: usize) -> *mut c_void {
    if xa.is_null() { return ptr::null_mut(); }
    with_lock(xa, |xa| erase_locked(xa, index))
}

extern "C" fn xa_find(xa: *mut LinuxXArray, index: *mut usize, max: usize, _filter: u32) -> *mut c_void {
    if xa.is_null() || index.is_null() { return ptr::null_mut(); }
    // SAFETY: index is required non-null by the exported C contract.
    let start = unsafe { *index };
    let result = with_lock(xa, |xa| find_locked(xa, start, max));
    if let Some((found, entry)) = result { unsafe { *index = found; } entry } else { ptr::null_mut() }
}

extern "C" fn xa_find_after(xa: *mut LinuxXArray, index: *mut usize, max: usize, filter: u32) -> *mut c_void {
    if xa.is_null() || index.is_null() { return ptr::null_mut(); }
    // SAFETY: index is required non-null by the exported C contract.
    let Some(start) = (unsafe { (*index).checked_add(1) }) else { return ptr::null_mut(); };
    let result = with_lock(xa, |xa| find_locked(xa, start, max));
    if let Some((found, entry)) = result { unsafe { *index = found; } entry } else { let _ = filter; ptr::null_mut() }
}

extern "C" fn xa_destroy(xa: *mut LinuxXArray) {
    if xa.is_null() { return; }
    with_lock(xa, destroy_locked);
}

pub(crate) fn with_lock<T>(xa: *mut LinuxXArray, f: impl FnOnce(&mut LinuxXArray) -> T) -> T {
    // SAFETY: caller checked xa is non-null and the embedded spinlock serializes all tree access.
    unsafe { spin_lock((&mut (*xa).lock) as *mut LinuxSpinlock); let result = f(&mut *xa); spin_unlock((&mut (*xa).lock) as *mut LinuxSpinlock); result }
}

pub(crate) fn load_locked(xa: &LinuxXArray, index: usize) -> *mut c_void {
    if xa.head.is_null() { return ptr::null_mut(); }
    if !is_node(xa.head) { return if index == 0 { xa.head } else { ptr::null_mut() }; }
    let mut n = node(xa.head);
    let root_shift = unsafe { (*n).shift };
    if root_shift < usize::BITS as u8 - CHUNK_SHIFT && index >> (root_shift + CHUNK_SHIFT) != 0 { return ptr::null_mut(); }
    loop {
        // SAFETY: every tagged node came from Box::into_raw and remains owned by this xarray.
        let shift = unsafe { (*n).shift };
        let entry = unsafe { (*n).slots[(index >> shift) & (CHUNK_SIZE - 1)] };
        if shift == 0 || entry.is_null() { return entry; }
        if !is_node(entry) { return ptr::null_mut(); }
        n = node(entry);
    }
}

pub(crate) fn store_locked(xa: &mut LinuxXArray, index: usize, entry: *mut c_void) {
    if xa.head.is_null() && index == 0 { xa.head = entry; return; }
    if !is_node(xa.head) {
        let old = xa.head; xa.head = tagged(new_node(0));
        unsafe { (*node(xa.head)).slots[0] = old; }
    }
    let needed = root_shift(index);
    while unsafe { (*node(xa.head)).shift } < needed {
        let old = xa.head; xa.head = tagged(new_node(unsafe { (*node(old)).shift } + CHUNK_SHIFT));
        unsafe { (*node(xa.head)).slots[0] = old; }
    }
    let mut n = node(xa.head);
    loop {
        let shift = unsafe { (*n).shift };
        let slot = (index >> shift) & (CHUNK_SIZE - 1);
        if shift == 0 { unsafe { (*n).slots[slot] = entry; } return; }
        let child = unsafe { (*n).slots[slot] };
        if child.is_null() { let child = tagged(new_node(shift - CHUNK_SHIFT)); unsafe { (*n).slots[slot] = child; } n = node(child); }
        else { n = node(child); }
    }
}

pub(crate) fn erase_locked(xa: &mut LinuxXArray, index: usize) -> *mut c_void {
    let old = load_locked(xa, index);
    if old.is_null() { return old; }
    if !is_node(xa.head) { xa.head = ptr::null_mut(); return old; }
    let mut n = node(xa.head);
    loop { let shift = unsafe { (*n).shift }; let slot = (index >> shift) & (CHUNK_SIZE - 1); if shift == 0 { unsafe { (*n).slots[slot] = ptr::null_mut(); } return old; } n = node(unsafe { (*n).slots[slot] }); }
}

pub(crate) fn destroy_locked(xa: &mut LinuxXArray) {
    if is_node(xa.head) { free_node(node(xa.head)); }
    xa.head = ptr::null_mut();
}

pub(crate) fn find_locked(xa: &LinuxXArray, start: usize, max: usize) -> Option<(usize, *mut c_void)> {
    if start > max || xa.head.is_null() { return None; }
    if !is_node(xa.head) { return (start == 0).then_some((0, xa.head)); }
    find_node(node(xa.head), 0, start, max)
}

fn find_node(n: *mut XaNode, base: usize, start: usize, max: usize) -> Option<(usize, *mut c_void)> {
    let shift = unsafe { (*n).shift }; let width = 1usize << shift;
    for slot in 0..CHUNK_SIZE { let child_base = base | (slot << shift); if child_base > max || child_base.saturating_add(width - 1) < start { continue; } let entry = unsafe { (*n).slots[slot] }; if entry.is_null() { continue; } if shift == 0 { return Some((child_base, entry)); } if let Some(found) = find_node(node(entry), child_base, start, max) { return Some(found); } }
    None
}

fn root_shift(index: usize) -> u8 {
    let mut shift = 0;
    while shift < usize::BITS as u8 - CHUNK_SHIFT && index >> (shift + CHUNK_SHIFT) != 0 { shift += CHUNK_SHIFT; }
    shift
}
fn new_node(shift: u8) -> *mut XaNode { Box::into_raw(Box::new(XaNode { shift, slots: [ptr::null_mut(); CHUNK_SIZE] })) }
fn tagged(n: *mut XaNode) -> *mut c_void { ((n as usize) + NODE_TAG) as *mut c_void }
fn is_node(entry: *mut c_void) -> bool { (entry as usize & NODE_MASK) == NODE_TAG }
fn node(entry: *mut c_void) -> *mut XaNode { ((entry as usize) - NODE_TAG) as *mut XaNode }
fn invalid_entry(entry: *mut c_void) -> bool { !entry.is_null() && (entry as usize & NODE_MASK) != 0 }
fn err_ptr<T>(errno: i32) -> *mut T { (usize::MAX - errno as usize + 1) as *mut T }

fn free_node(n: *mut XaNode) {
    for entry in unsafe { (*n).slots } { if is_node(entry) { free_node(node(entry)); } }
    // SAFETY: n was allocated by new_node and is reached exactly once from this tree.
    unsafe { drop(Box::from_raw(n)); }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn radix_paths_find_replace_and_destroy() { let _m = crate::test_serial::claim(); let mut xa = LinuxXArray { lock: LinuxSpinlock { state: 0 }, flags: 0, head: ptr::null_mut() }; let a = 0x1000usize as *mut c_void; let b = 0x2000usize as *mut c_void; let c = 0x3000usize as *mut c_void; xa_init_flags(&mut xa, 0); assert_eq!(xa_insert(&mut xa, 0, a, 0), 0); assert_eq!(xa_insert(&mut xa, 64, b, 0), 0); assert_eq!(xa_store(&mut xa, 1 << 20, c, 0), ptr::null_mut()); assert_eq!(xa_load(&mut xa, 64), b); let mut i = 1; assert_eq!(xa_find(&mut xa, &mut i, usize::MAX, 0), b); assert_eq!(i, 64); assert_eq!(xa_find_after(&mut xa, &mut i, usize::MAX, 0), c); assert_eq!(i, 1 << 20); assert_eq!(xa_erase(&mut xa, 64), b); assert_eq!(xa_load(&mut xa, 64), ptr::null_mut()); xa_destroy(&mut xa); assert!(xa.head.is_null()); }
}
