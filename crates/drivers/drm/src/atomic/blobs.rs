//! User-created DRM property blob lifetime and copying.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use sync::{Spinlock, TaskList as AtomicLockClass};
use syscall::errno::Errno;

use crate::{DrmModeCreateBlob, DrmModeDestroyBlob};

struct Blob { id: u32, bytes: Vec<u8> }

/// `drm_property_create_blob` rejects only an empty blob or one that cannot be
/// described alongside its header: `length > INT_MAX - sizeof(*blob)`. Anything
/// within that bound is an allocation question, not a validity one, so an
/// oversize-but-legal request is ENOMEM rather than EINVAL.
const MAX_USER_BLOB_BYTES: u32 = i32::MAX as u32 - core::mem::size_of::<Blob>() as u32;

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
    let Ok(mut req) = crate::uarg::read_arg::<DrmModeCreateBlob>(arg) else { return efault() };
    if req.length == 0 || req.length > MAX_USER_BLOB_BYTES || !user_ok(req.data, req.length as u64) {
        return einval();
    }
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(req.length as usize).is_err() {
        return -(Errno::Enomem.as_i32() as i64);
    }
    bytes.resize(req.length as usize, 0);
    if uaccess::copy_from_user(&mut bytes, req.data).is_err() { return efault(); }
    let id = NEXT_BLOB_ID.fetch_add(1, Ordering::AcqRel).max(0x100);
    BLOBS.lock().push(Blob { id, bytes });
    req.blob_id = id;
    if crate::uarg::write_arg(arg, req).is_err() { return efault(); }
    0
}

/// Release a named user blob. # C: O(n)
pub fn destroy_blob(arg: u64) -> i64 {
    if !user_ok(arg, core::mem::size_of::<DrmModeDestroyBlob>() as u64) { return efault(); }
    let Ok(req) = crate::uarg::read_arg::<DrmModeDestroyBlob>(arg) else { return efault() };
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
        if uaccess::copy_to_user(data_ptr, &blob.bytes).is_err() { return Some(efault()); }
    }
    Some(len as i64)
}

/// Test whether a blob is exactly one `drm_mode_modeinfo`. # C: O(n)
pub fn mode_blob(blob_id: u32) -> bool {
    BLOBS.lock().iter().any(|blob| blob.id == blob_id
        && blob.bytes.len() == core::mem::size_of::<crate::DrmModeModeinfo>())
}
