// Copy shim for the two event-mask commands. Every rule it applies lives in
// `crate::evdev_mask`; this file only moves bytes across the ABI boundary.

use syscall::errno::Errno;

use crate::devfs::shared::EvdevOpen;
use crate::evdev_mask as policy;

use super::{err, uread, uwrite, uzero, valid_user_range};

/// Serve EVIOCGMASK / EVIOCSMASK for one open evdev client.
/// # C: O(codes_size)
pub(super) fn handle_mask(opened: &EvdevOpen, nr: u32, arg: u64) -> i64 {
    if !valid_user_range(arg, policy::INPUT_MASK_BYTES as u64) {
        return err(Errno::Efault);
    }
    let mut raw = [0u8; policy::INPUT_MASK_BYTES];
    // SAFETY: valid_user_range accepted arg for the whole fixed-length input_mask descriptor.
    unsafe { uread(arg, &mut raw); }
    let desc = policy::parse_input_mask(&raw);
    let cnt = policy::mask_cnt(desc.ev_type);
    if nr == crate::EVIOCSMASK_NR as u32 {
        return set_mask(opened, &desc, cnt);
    }
    get_mask(opened, &desc, cnt)
}

fn set_mask(opened: &EvdevOpen, desc: &policy::InputMask, cnt: usize) -> i64 {
    let len = match policy::plan_set(cnt, desc.codes_size) {
        // Unknown types are accepted and dropped so callers may mask types this
        // build does not know; refusing them would break forward compatibility.
        policy::SetMaskPlan::Ignore => return 0,
        policy::SetMaskPlan::Misaligned => return err(Errno::Einval),
        policy::SetMaskPlan::Copy(len) => len,
    };
    let mut codes = [0u8; policy::MASK_MAX_BYTES];
    if len > 0 {
        if !valid_user_range(desc.codes_ptr, len as u64) {
            return err(Errno::Efault);
        }
        // SAFETY: valid_user_range accepted codes_ptr for the len bytes this mask reads.
        unsafe { uread(desc.codes_ptr, &mut codes[..len]); }
    }
    if opened.mask_set(desc.ev_type, &codes[..len]) { 0 } else { err(Errno::Einval) }
}

fn get_mask(opened: &EvdevOpen, desc: &policy::InputMask, cnt: usize) -> i64 {
    let plan = policy::plan_get(cnt, desc.codes_size);
    if desc.codes_size > 0 && !valid_user_range(desc.codes_ptr, u64::from(desc.codes_size)) {
        return err(Errno::Efault);
    }
    // A client that installed no mask for this type receives all-ones: every
    // code of the type is delivered to it.
    let mut codes = [policy::MASK_UNSET_FILL; policy::MASK_MAX_BYTES];
    let copy = policy::get_copy_len(cnt, plan);
    let payload = match opened.mask_get(desc.ev_type, &mut codes[..copy]) {
        Some(_) => copy,
        None => plan.payload.min(policy::MASK_MAX_BYTES),
    };
    if payload > 0 {
        // SAFETY: valid_user_range accepted codes_ptr for codes_size bytes, and payload <= codes_size.
        unsafe { uwrite(desc.codes_ptr, &codes[..payload], payload); }
    }
    if plan.tail_len > 0 {
        // SAFETY: valid_user_range accepted codes_ptr for codes_size bytes, and this tail ends there.
        unsafe { uzero(desc.codes_ptr + plan.tail_off as u64, plan.tail_len); }
    }
    0
}
