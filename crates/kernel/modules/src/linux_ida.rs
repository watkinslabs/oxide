// Module manifest: Linux IDA bitmap allocator backed by the canonical XArray.

extern crate alloc;

use alloc::boxed::Box;
use core::{ffi::c_void, ptr};
use crate::linux_xarray::{destroy_locked, erase_locked, find_locked, load_locked, store_locked, with_lock, LinuxXArray};

const IDA_BITMAP_BITS: usize = 128 * usize::BITS as usize;
const SMALL_BITS: usize = usize::BITS as usize - 1;
const LINUX_ENOSPC: i32 = 28;
const INT_MAX: u32 = i32::MAX as u32;

#[repr(C)]
pub struct LinuxIda { xa: LinuxXArray }
struct IdaBitmap { bits: [usize; 128] }

/// Register Linux IDA allocator exports.
/// # C: O(1)
pub fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("ida_init", ida_init as *const () as usize),
        ("ida_alloc_range", ida_alloc_range as *const () as usize),
        ("ida_free", ida_free as *const () as usize),
        ("ida_destroy", ida_destroy as *const () as usize),
    ] { export(name, addr, false); }
}

extern "C" fn ida_init(ida: *mut LinuxIda) {
    if ida.is_null() { return; }
    // SAFETY: ida names caller-owned storage and the xarray initializer owns its complete ABI state.
    unsafe { crate::linux_xarray::xa_init_flags((&mut (*ida).xa) as *mut LinuxXArray, 5); }
}

extern "C" fn ida_alloc_range(ida: *mut LinuxIda, min: u32, max: u32, _gfp: u32) -> i32 {
    if ida.is_null() || min > INT_MAX { return -LINUX_ENOSPC; }
    let max = max.min(INT_MAX);
    if min > max { return -LINUX_ENOSPC; }
    // SAFETY: ida is non-null and its embedded xarray serializes allocation with release and destruction.
    unsafe { with_lock((&mut (*ida).xa) as *mut LinuxXArray, |xa| allocate_locked(xa, min as usize, max as usize)) }
}

extern "C" fn ida_free(ida: *mut LinuxIda, id: u32) {
    if ida.is_null() || id > INT_MAX { return; }
    // SAFETY: ida is non-null and the xarray lock protects the entry and its bitmap.
    unsafe { with_lock((&mut (*ida).xa) as *mut LinuxXArray, |xa| free_locked(xa, id as usize)); }
}

extern "C" fn ida_destroy(ida: *mut LinuxIda) {
    if ida.is_null() { return; }
    // SAFETY: ida is non-null and the xarray lock protects complete teardown.
    unsafe { with_lock((&mut (*ida).xa) as *mut LinuxXArray, |xa| { let end = INT_MAX as usize / IDA_BITMAP_BITS; let mut chunk = 0; while let Some((found, entry)) = find_locked(xa, chunk, end) { if !is_value(entry) { drop(Box::from_raw(entry.cast::<IdaBitmap>())); } erase_locked(xa, found); chunk = found.saturating_add(1); } destroy_locked(xa); }); }
}

fn allocate_locked(xa: &mut LinuxXArray, min: usize, max: usize) -> i32 {
    let mut chunk = min / IDA_BITMAP_BITS;
    let end = max / IDA_BITMAP_BITS;
    let mut bit = min % IDA_BITMAP_BITS;
    while chunk <= end {
        let entry = load_locked(xa, chunk);
        if entry.is_null() {
            if bit < SMALL_BITS { let chosen = bit; store_locked(xa, chunk, value(1usize << chosen)); return (chunk * IDA_BITMAP_BITS + chosen) as i32; }
            let mut bitmap = Box::new(IdaBitmap { bits: [0; 128] });
            if let Some(chosen) = first_zero(&bitmap.bits, bit, max.saturating_sub(chunk * IDA_BITMAP_BITS)) { set_bit(&mut bitmap.bits, chosen); let raw = Box::into_raw(bitmap).cast::<c_void>(); store_locked(xa, chunk, raw); return (chunk * IDA_BITMAP_BITS + chosen) as i32; }
        } else if is_value(entry) {
            let bits = decode_value(entry);
            if let Some(chosen) = first_zero_word(bits, bit.min(SMALL_BITS)) { let result = chunk * IDA_BITMAP_BITS + chosen; if result <= max { store_locked(xa, chunk, value(bits | (1usize << chosen))); return result as i32; } }
            let mut bitmap = Box::new(IdaBitmap { bits: [0; 128] }); bitmap.bits[0] = bits;
            if let Some(chosen) = first_zero(&bitmap.bits, bit, max.saturating_sub(chunk * IDA_BITMAP_BITS)) { set_bit(&mut bitmap.bits, chosen); let raw = Box::into_raw(bitmap).cast::<c_void>(); store_locked(xa, chunk, raw); return (chunk * IDA_BITMAP_BITS + chosen) as i32; }
        } else {
            let bitmap = unsafe { &mut *entry.cast::<IdaBitmap>() };
            if let Some(chosen) = first_zero(&bitmap.bits, bit, max.saturating_sub(chunk * IDA_BITMAP_BITS)) { set_bit(&mut bitmap.bits, chosen); return (chunk * IDA_BITMAP_BITS + chosen) as i32; }
        }
        chunk += 1; bit = 0;
    }
    -LINUX_ENOSPC
}

fn free_locked(xa: &mut LinuxXArray, id: usize) {
    let chunk = id / IDA_BITMAP_BITS; let bit = id % IDA_BITMAP_BITS; let entry = load_locked(xa, chunk);
    if entry.is_null() { return; }
    if is_value(entry) { if bit >= SMALL_BITS { return; } let bits = decode_value(entry); if bits & (1usize << bit) == 0 { return; } let new = bits & !(1usize << bit); if new == 0 { erase_locked(xa, chunk); } else { store_locked(xa, chunk, value(new)); } return; }
    let bitmap = unsafe { &mut *entry.cast::<IdaBitmap>() }; if !test_bit(&bitmap.bits, bit) { return; } clear_bit(&mut bitmap.bits, bit); if bitmap.bits.iter().all(|word| *word == 0) { let old = erase_locked(xa, chunk); unsafe { drop(Box::from_raw(old.cast::<IdaBitmap>())); } }
}

fn first_zero(bits: &[usize; 128], start: usize, limit: usize) -> Option<usize> { let limit = limit.min(IDA_BITMAP_BITS - 1); (start..=limit).find(|bit| !test_bit(bits, *bit)) }
fn first_zero_word(bits: usize, start: usize) -> Option<usize> { (start..SMALL_BITS).find(|bit| bits & (1usize << bit) == 0) }
fn test_bit(bits: &[usize; 128], bit: usize) -> bool { bits[bit / usize::BITS as usize] & (1usize << (bit % usize::BITS as usize)) != 0 }
fn set_bit(bits: &mut [usize; 128], bit: usize) { bits[bit / usize::BITS as usize] |= 1usize << (bit % usize::BITS as usize); }
fn clear_bit(bits: &mut [usize; 128], bit: usize) { bits[bit / usize::BITS as usize] &= !(1usize << (bit % usize::BITS as usize)); }
fn value(bits: usize) -> *mut c_void { ((bits << 1) | 1) as *mut c_void }
fn is_value(entry: *mut c_void) -> bool { entry as usize & 1 != 0 }
fn decode_value(entry: *mut c_void) -> usize { entry as usize >> 1 }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux_sync::LinuxSpinlock;
    #[test] fn allocates_ranges_reuses_releases_and_tears_down() { let _m = crate::test_serial::claim(); let mut ida = LinuxIda { xa: LinuxXArray { lock: LinuxSpinlock { state: 0 }, flags: 0, head: ptr::null_mut() } }; ida_init(&mut ida); assert_eq!(ida_alloc_range(&mut ida, 3, 9, 0), 3); assert_eq!(ida_alloc_range(&mut ida, 3, 9, 0), 4); ida_free(&mut ida, 3); assert_eq!(ida_alloc_range(&mut ida, 3, 9, 0), 3); assert_eq!(ida_alloc_range(&mut ida, 127, 130, 0), 127); assert_eq!(ida_alloc_range(&mut ida, 128, 130, 0), 128); ida_destroy(&mut ida); assert_eq!(ida_alloc_range(&mut ida, 0, 0, 0), 0); }
}
