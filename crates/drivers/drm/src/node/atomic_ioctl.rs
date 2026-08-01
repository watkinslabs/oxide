//! Card-node `MODE_ATOMIC` UAPI parsing before core atomic validation.

extern crate alloc;

use alloc::{sync::Arc, vec::Vec};
use syscall::errno::Errno;

use super::{auth::atomic_property_count, uapi::{DrmModeAtomic, DRM_MODE_ATOMIC_SUPPORTED_FLAGS}};
use crate::DrmDriver;

const MAX_ATOMIC_OBJECTS: u32 = 4096;
const MAX_ATOMIC_PROPERTIES: u64 = 65536;

fn efault() -> i64 { -(Errno::Efault.as_i32() as i64) }
fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }

/// Flattened property index after an object contributing `n` properties, or
/// `None` when that would pass `count`.
///
/// `count` is the total summed by an EARLIER pass over the same user array, and
/// it is what `props_ptr` / `prop_values_ptr` were range-checked against.
/// Userspace can rewrite `count_props[]` between the two passes, so the
/// per-object count re-read in the copy loop is untrusted and the running total
/// is re-checked here. Without this the flattened index walks past the checked
/// extent and reads memory outside it.
/// # C: O(1)
fn advance_pos(pos: u64, n: u32, count: u64) -> Option<u64> {
    let end = pos.checked_add(n as u64)?;
    if end > count { return None; }
    Some(end)
}

/// Parse Linux's packed atomic arrays and transfer only copied tuples to core. # C: O(tuples)
pub(super) fn handle(card_id: u32, card: &Arc<dyn DrmDriver>, token: u64, arg: u64) -> i64 {
    let Ok(req) = crate::uarg::read_arg::<DrmModeAtomic>(arg) else { return efault() };
    if req.count_objs > MAX_ATOMIC_OBJECTS || req.reserved != 0
        || req.flags & !DRM_MODE_ATOMIC_SUPPORTED_FLAGS != 0
        || req.flags & crate::DRM_MODE_PAGE_FLIP_ASYNC != 0 { return einval(); }
    if req.count_objs == 0 { return 0; }
    let count = match atomic_property_count(req.count_props_ptr, req.count_objs) {
        Ok(count) if count <= MAX_ATOMIC_PROPERTIES => count,
        Ok(_) => return einval(), Err(()) => return efault(),
    };
    let mut tuples = Vec::with_capacity(count as usize);
    let mut pos = 0u64;
    for obj_idx in 0..req.count_objs {
        let off = obj_idx as u64 * 4;
        let (Ok(obj), Ok(n)) = (
            crate::uarg::read_arg::<u32>(req.objs_ptr.wrapping_add(off)),
            crate::uarg::read_arg::<u32>(req.count_props_ptr.wrapping_add(off)),
        ) else { return efault() };
        let Some(next) = advance_pos(pos, n, count) else { return efault() };
        for _ in 0..n {
            let (Ok(prop), Ok(value)) = (
                crate::uarg::read_arg::<u32>(req.props_ptr.wrapping_add(pos * 4)),
                crate::uarg::read_arg::<u64>(req.prop_values_ptr.wrapping_add(pos * 8)),
            ) else { return efault() };
            tuples.push((obj, prop, value));
            pos += 1;
        }
        pos = next;
    }
    crate::atomic::commit(card_id, card, token, req.flags, req.user_data, &tuples)
}

#[cfg(test)]
mod tests {
    use super::advance_pos;

    #[test]
    fn a_running_total_within_the_validated_count_advances() {
        assert_eq!(advance_pos(0, 3, 10), Some(3));
        assert_eq!(advance_pos(7, 3, 10), Some(10));
    }

    /// The count re-read from user memory may have grown since the pass that
    /// sized the property arrays; the extra properties must not be copied.
    #[test]
    fn a_count_grown_since_validation_is_refused() {
        assert_eq!(advance_pos(7, 4, 10), None);
        assert_eq!(advance_pos(0, u32::MAX, 10), None);
    }

    #[test]
    fn an_overflowing_running_total_is_refused() {
        assert_eq!(advance_pos(u64::MAX, 1, u64::MAX), None);
    }
}
