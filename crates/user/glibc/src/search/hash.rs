// hsearch(3) family (docs/59§6 G8): string-keyed hash table. Open-addressing
// with linear probing; the probe sequence is private (callers observe only
// FIND/ENTER results), so any hash works. _r variants take a caller-owned
// struct hsearch_data {table,size,filled}; the global hsearch/hcreate/hdestroy
// wrap one process-global table. ENTER=1 FIND=0 (glibc). C ABI only.
#![cfg(feature = "freestanding")]
use core::ffi::c_void;
use crate::string::cmp::strcmp_impl;

const ENOMEM: i32 = 12;
const ESRCH: i32 = 3;

#[repr(C)]
pub struct ENTRY { pub key: *mut u8, pub data: *mut c_void }
#[repr(C)]
struct Slot { used: u32, _pad: u32, entry: ENTRY }
#[repr(C)]
pub struct HsearchData { table: *mut Slot, size: u32, filled: u32 }

extern "C" { fn calloc(n: usize, sz: usize) -> *mut c_void; fn free(p: *mut c_void); }

fn is_prime(n: u32) -> bool {
    if n < 2 { return false; }
    let mut i = 2u32;
    while i * i <= n { if n.is_multiple_of(i) { return false; } i += 1; }
    true
}
fn next_prime(mut n: u32) -> u32 {
    if n < 3 { return 3; }
    if n.is_multiple_of(2) { n += 1; }
    while !is_prime(n) { n += 2; }
    n
}

unsafe fn hash(key: *const u8) -> u64 {
    // SAFETY: key is a NUL-terminated C string; djb2 over its bytes.
    unsafe { let mut h = 5381u64; let mut i = 0; loop { let c = *key.add(i); if c == 0 { break; } h = h.wrapping_mul(33).wrapping_add(c as u64); i += 1; } h }
}

// # C: int hcreate_r(size_t nel, struct hsearch_data *htab)
#[no_mangle]
pub unsafe extern "C" fn hcreate_r(nel: usize, htab: *mut HsearchData) -> i32 {
    // SAFETY: htab is a writable, caller-zeroed struct hsearch_data. Size the
    // table to a prime > nel (glibc keeps load < 1) and calloc the slots.
    unsafe {
        if htab.is_null() || !(*htab).table.is_null() { return 0; }
        let size = next_prime((nel + nel / 4 + 1) as u32);
        let t = calloc(size as usize, core::mem::size_of::<Slot>()) as *mut Slot;
        if t.is_null() { crate::internal::errno::set(ENOMEM); return 0; }
        (*htab).table = t; (*htab).size = size; (*htab).filled = 0;
        1
    }
}

// # C: int hsearch_r(ENTRY item, ACTION action, ENTRY **retval, struct hsearch_data *htab)
#[no_mangle]
pub unsafe extern "C" fn hsearch_r(item: ENTRY, action: i32, retval: *mut *mut ENTRY, htab: *mut HsearchData) -> i32 {
    // SAFETY: htab is an initialised table; item.key is a NUL-terminated string;
    // retval is a writable out-param. Linear-probe for the key; ENTER inserts on
    // a miss (ESRCH+0 when full), FIND returns 0 on a miss.
    unsafe {
        if htab.is_null() || (*htab).table.is_null() { return 0; }
        let size = (*htab).size;
        let mut idx = (hash(item.key) % size as u64) as u32;
        let mut probed = 0u32;
        while probed < size {
            let slot = (*htab).table.add(idx as usize);
            if (*slot).used == 0 {
                if action == 1 { // ENTER
                    (*slot).used = 1;
                    (*slot).entry = ENTRY { key: item.key, data: item.data };
                    (*htab).filled += 1;
                    *retval = core::ptr::addr_of_mut!((*slot).entry);
                    return 1;
                }
                *retval = core::ptr::null_mut(); // FIND miss
                return 0;
            }
            if strcmp_impl((*slot).entry.key, item.key) == 0 {
                *retval = core::ptr::addr_of_mut!((*slot).entry);
                return 1;
            }
            idx = (idx + 1) % size;
            probed += 1;
        }
        if action == 1 { crate::internal::errno::set(ESRCH); }
        *retval = core::ptr::null_mut();
        0
    }
}

// # C: void hdestroy_r(struct hsearch_data *htab)
#[no_mangle]
pub unsafe extern "C" fn hdestroy_r(htab: *mut HsearchData) {
    // SAFETY: htab is an initialised table; free its slot array and reset.
    unsafe { if !htab.is_null() && !(*htab).table.is_null() { free((*htab).table as *mut c_void); (*htab).table = core::ptr::null_mut(); (*htab).size = 0; (*htab).filled = 0; } }
}

mod global {
    use super::*;
    use core::cell::UnsafeCell;
    struct G(UnsafeCell<HsearchData>);
    // SAFETY: the process-global hsearch table; single-threaded until TLS.
    unsafe impl Sync for G {}
    static TAB: G = G(UnsafeCell::new(HsearchData { table: core::ptr::null_mut(), size: 0, filled: 0 }));

    // # C: int hcreate(size_t nel)
    #[no_mangle]
    pub unsafe extern "C" fn hcreate(nel: usize) -> i32 {
        // SAFETY: routes to hcreate_r on the process-global table.
        unsafe { hcreate_r(nel, TAB.0.get()) }
    }
    // # C: ENTRY *hsearch(ENTRY item, ACTION action)
    #[no_mangle]
    pub unsafe extern "C" fn hsearch(item: ENTRY, action: i32) -> *mut ENTRY {
        // SAFETY: routes to hsearch_r on the process-global table.
        unsafe { let mut rv = core::ptr::null_mut(); hsearch_r(item, action, &mut rv, TAB.0.get()); rv }
    }
    // # C: void hdestroy(void)
    #[no_mangle]
    pub unsafe extern "C" fn hdestroy() {
        // SAFETY: frees the process-global table.
        unsafe { hdestroy_r(TAB.0.get()); }
    }
}
