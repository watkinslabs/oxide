//! Card-node `MODE_ATOMIC` UAPI parsing before core atomic validation.

extern crate alloc;

use alloc::{sync::Arc, vec::Vec};
use syscall::errno::Errno;

use super::{auth::{atomic_property_count, valid_user_range}, uapi::{DrmModeAtomic, DRM_MODE_ATOMIC_SUPPORTED_FLAGS}};
use crate::DrmDriver;

const MAX_ATOMIC_OBJECTS: u32 = 4096;
const MAX_ATOMIC_PROPERTIES: u64 = 65536;

fn efault() -> i64 { -(Errno::Efault.as_i32() as i64) }
fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }

/// Parse Linux's packed atomic arrays and transfer only copied tuples to core. # C: O(tuples)
pub(super) fn handle(card_id: u32, card: &Arc<dyn DrmDriver>, token: u64, arg: u64) -> i64 {
    if !valid_user_range(arg, core::mem::size_of::<DrmModeAtomic>() as u64) { return efault(); }
    // SAFETY: complete fixed drm_mode_atomic structure was validated above.
    let req = unsafe { core::ptr::read_volatile(arg as *const DrmModeAtomic) };
    if req.count_objs > MAX_ATOMIC_OBJECTS || req.reserved != 0
        || req.flags & !DRM_MODE_ATOMIC_SUPPORTED_FLAGS != 0
        || req.flags & crate::DRM_MODE_PAGE_FLIP_ASYNC != 0 { return einval(); }
    if req.count_objs == 0 { return 0; }
    let obj_bytes = req.count_objs as u64 * 4;
    if !valid_user_range(req.objs_ptr, obj_bytes) { return efault(); }
    let count = match atomic_property_count(req.count_props_ptr, req.count_objs) {
        Ok(count) if count <= MAX_ATOMIC_PROPERTIES => count,
        Ok(_) => return einval(), Err(()) => return efault(),
    };
    let prop_bytes = match count.checked_mul(4) { Some(n) if n == 0 || valid_user_range(req.props_ptr, n) => n, _ => return efault() };
    let value_bytes = match count.checked_mul(8) { Some(n) if n == 0 || valid_user_range(req.prop_values_ptr, n) => n, _ => return efault() };
    let _ = (prop_bytes, value_bytes);
    let mut tuples = Vec::with_capacity(count as usize);
    let mut pos = 0u64;
    for obj_idx in 0..req.count_objs {
        // SAFETY: both object and count arrays were range-validated above.
        let obj = unsafe { core::ptr::read_volatile((req.objs_ptr + obj_idx as u64 * 4) as *const u32) };
        let n = unsafe { core::ptr::read_volatile((req.count_props_ptr + obj_idx as u64 * 4) as *const u32) };
        for _ in 0..n {
            // SAFETY: flattened property/value arrays were range-validated above.
            let prop = unsafe { core::ptr::read_volatile((req.props_ptr + pos * 4) as *const u32) };
            let value = unsafe { core::ptr::read_volatile((req.prop_values_ptr + pos * 8) as *const u64) };
            tuples.push((obj, prop, value));
            pos += 1;
        }
    }
    crate::atomic::commit(card_id, card, token, req.flags, req.user_data, &tuples)
}
