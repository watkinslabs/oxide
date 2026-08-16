//! Control ranges: whether a driver's declaration is coherent, and how a
//! caller's value is snapped onto it.

use syscall::errno::Errno;

use crate::uapi::ctrl_ids as cid;

/// Is a driver's declared range coherent for this control type?
///
/// A range that is not is a driver bug, and the reference refuses to register
/// the control rather than let an application negotiate against nonsense. The
/// rules differ per type, so they are enumerated rather than generalised:
/// a boolean has no step to choose, a bitmask has no minimum, and a menu's
/// skip mask only reaches the first 64 entries.
/// # C: O(1)
pub fn check_range(ctrl_type: u32, minimum: i64, maximum: i64, step: u64, default_value: i64)
    -> Result<(), Errno>
{
    match ctrl_type {
        cid::CTRL_TYPE_BOOLEAN => {
            if step != 1 || maximum > 1 || minimum < 0 { return Err(Errno::Erange); }
            Ok(())
        }
        cid::CTRL_TYPE_INTEGER | cid::CTRL_TYPE_INTEGER64
        | cid::CTRL_TYPE_U8 | cid::CTRL_TYPE_U16 | cid::CTRL_TYPE_U32 => {
            if step == 0 || minimum > maximum { return Err(Errno::Erange); }
            if default_value < minimum || default_value > maximum { return Err(Errno::Erange); }
            Ok(())
        }
        cid::CTRL_TYPE_BITMASK => {
            // A bitmask's `maximum` is the set of legal bits, so a zero
            // maximum admits nothing and a default outside it is unreachable.
            if step != 0 || minimum != 0 || maximum == 0 { return Err(Errno::Erange); }
            if default_value & !maximum != 0 { return Err(Errno::Erange); }
            Ok(())
        }
        cid::CTRL_TYPE_MENU | cid::CTRL_TYPE_INTEGER_MENU => {
            if minimum > maximum || minimum < 0 { return Err(Errno::Erange); }
            if default_value < minimum || default_value > maximum { return Err(Errno::Erange); }
            // `step` doubles as the skip mask for a menu, and a mask can only
            // describe the first 64 entries.
            if step != 0 && maximum >= 64 { return Err(Errno::Erange); }
            // A default the driver also declared unusable is a contradiction,
            // and it is `EINVAL` rather than `ERANGE` because the range itself
            // is fine — the choice within it is not.
            if default_value < 64 && step & (1u64 << default_value) != 0 { return Err(Errno::Einval); }
            Ok(())
        }
        cid::CTRL_TYPE_STRING => {
            if minimum > maximum || minimum < 0 || step < 1 || default_value != 0 {
                return Err(Errno::Erange);
            }
            Ok(())
        }
        cid::CTRL_TYPE_BUTTON | cid::CTRL_TYPE_CTRL_CLASS => Ok(()),
        _ => Ok(()),
    }
}

/// Snap `value` onto the legal grid `minimum + k*step` inside
/// `[minimum, maximum]`.
///
/// Round to the nearest legal value, half upward, then clamp, then truncate
/// onto the grid. The maximum is a special case handled before the rounding
/// addition: adding half a step to a value already at the top would overflow
/// past the maximum for a control whose range ends on a non-grid value, and
/// the caller asking for the maximum must get exactly the maximum.
/// # C: O(1)
pub fn round_to_range(mut value: i64, minimum: i64, maximum: i64, step: u64) -> i64 {
    let step = if step == 0 { 1 } else { step };
    let half = (step / 2) as i64;
    if maximum >= 0 && value >= maximum.saturating_sub(half) {
        value = maximum;
    } else {
        value = value.saturating_add(half);
    }
    if value < minimum { value = minimum; }
    if value > maximum { value = maximum; }
    let offset = value.wrapping_sub(minimum) as u64;
    let offset = step.saturating_mul(offset / step);
    minimum.saturating_add(offset as i64)
}

/// Validate a caller's value for one control, returning the value that will
/// actually be stored.
///
/// A menu index outside the range, or one the driver marked unusable, is
/// `EINVAL` and not silently clamped — an application choosing "60 Hz" must
/// not have it turned into "50 Hz" behind its back. A plain integer, by
/// contrast, IS clamped, because that is the reference's contract for a
/// slider.
/// # C: O(1)
pub fn validate(ctrl_type: u32, value: i64, minimum: i64, maximum: i64, step: u64)
    -> Result<i64, Errno>
{
    match ctrl_type {
        cid::CTRL_TYPE_BUTTON => Ok(0),
        cid::CTRL_TYPE_BOOLEAN => Ok(if value != 0 { 1 } else { 0 }),
        // A bit the driver did not declare is dropped, not refused: the
        // reference masks the value against the legal set and stores the
        // remainder, so a program setting a bit this device lacks still gets
        // the bits it does have.
        cid::CTRL_TYPE_BITMASK => Ok(value & maximum),
        cid::CTRL_TYPE_MENU | cid::CTRL_TYPE_INTEGER_MENU => {
            if value < minimum || value > maximum { return Err(Errno::Erange); }
            if value < 64 && step & (1u64 << value) != 0 { return Err(Errno::Einval); }
            Ok(value)
        }
        _ => Ok(round_to_range(value, minimum, maximum, step)),
    }
}
