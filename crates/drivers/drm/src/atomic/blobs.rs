//! User-created DRM property blob lifetime and copying.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use sync::{Spinlock, TaskList as AtomicLockClass};
use syscall::errno::Errno;

use crate::{DrmModeCreateBlob, DrmModeDestroyBlob};

const MAX_USER_BLOB_BYTES: u32 = 64 * 1024;

struct Blob { id: u32, bytes: Vec<u8> }

static BLOBS: Spinlock<Vec<Blob>, AtomicLockClass> = Spinlock::new(Vec::new());
static NEXT_BLOB_ID: AtomicU32 = AtomicU32::new(0x100);

fn efault() -> i64 { -(Errno::Efault.as_i32() as i64) }
fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }

fn user_ok(ptr: u64, len: u64) -> bool {
    ptr != 0 && ptr < hal::USER_VA_END
        && ptr.checked_add(len).is_some_and(|end| end <= hal::USER_VA_END)
}

/// Copy a caller-owned byte sequence into a stable DRM blob object. # C: O(n)
pub fn create_blob(arg: u64) -> i64 {
    if !user_ok(arg, core::mem::size_of::<DrmModeCreateBlob>() as u64) { return efault(); }
    // SAFETY: fixed repr(C) UAPI structure range was validated above.
    let mut req = unsafe { core::ptr::read_volatile(arg as *const DrmModeCreateBlob) };
    if req.length == 0 || req.length > MAX_USER_BLOB_BYTES || !user_ok(req.data, req.length as u64) {
        return einval();
    }
    let mut bytes = Vec::with_capacity(req.length as usize);
    for off in 0..req.length as u64 {
        // SAFETY: [data,data+length) was validated and bytes are copied now.
        bytes.push(unsafe { core::ptr::read_volatile((req.data + off) as *const u8) });
    }
    let id = NEXT_BLOB_ID.fetch_add(1, Ordering::AcqRel).max(0x100);
    BLOBS.lock().push(Blob { id, bytes });
    req.blob_id = id;
    // SAFETY: the same fixed UAPI range is writable in the caller address space.
    unsafe { core::ptr::write_volatile(arg as *mut DrmModeCreateBlob, req); }
    0
}

/// Release a named user blob. # C: O(n)
pub fn destroy_blob(arg: u64) -> i64 {
    if !user_ok(arg, core::mem::size_of::<DrmModeDestroyBlob>() as u64) { return efault(); }
    // SAFETY: fixed 4-byte UAPI structure range was validated above.
    let req = unsafe { core::ptr::read_volatile(arg as *const DrmModeDestroyBlob) };
    let mut blobs = BLOBS.lock();
    match blobs.iter().position(|blob| blob.id == req.blob_id) {
        Some(pos) => { blobs.remove(pos); 0 }
        None => -(Errno::Enoent.as_i32() as i64),
    }
}

/// Copy a user-created blob to a GETPROPBLOB caller, returning its true size. # C: O(n)
pub fn get_blob(blob_id: u32, ulen: u32, data_ptr: u64) -> Option<i64> {
    let blobs = BLOBS.lock();
    let blob = blobs.iter().find(|blob| blob.id == blob_id)?;
    let len = blob.bytes.len() as u32;
    if ulen >= len && data_ptr != 0 {
        if !user_ok(data_ptr, len as u64) { return Some(efault()); }
        for (off, byte) in blob.bytes.iter().copied().enumerate() {
            // SAFETY: destination range was validated immediately above.
            unsafe { core::ptr::write_volatile((data_ptr + off as u64) as *mut u8, byte); }
        }
    }
    Some(len as i64)
}

/// Test whether a blob is exactly one `drm_mode_modeinfo`. # C: O(n)
pub fn mode_blob(blob_id: u32) -> bool {
    BLOBS.lock().iter().any(|blob| blob.id == blob_id
        && blob.bytes.len() == core::mem::size_of::<crate::DrmModeModeinfo>())
}
