//! Reading and writing control values: `G_CTRL`, `S_CTRL` and the extended
//! forms.

use syscall::errno::Errno;

use crate::uapi::ctrl_ids as cid;
use super::desc::Handler;
use super::range::validate;

/// May a caller read this control's value?
///
/// A disabled control is refused here even though `QUERYCTRL` still describes
/// it — the description is how an application learns the control exists and is
/// unavailable, and hiding it entirely would make an unavailable control
/// indistinguishable from one the device lacks. A write-only control has no
/// value to read, and a compound one does not fit the scalar interface.
/// # C: O(log n)
pub fn may_read(handler: &Handler, id: u32) -> Result<(), Errno> {
    let desc = handler.find(id).ok_or(Errno::Einval)?;
    let flags = handler.flags(id).unwrap_or(0);
    if flags & cid::CTRL_FLAG_DISABLED != 0 { return Err(Errno::Einval); }
    if flags & cid::CTRL_FLAG_WRITE_ONLY != 0 { return Err(Errno::Eacces); }
    if desc.is_compound() { return Err(Errno::Einval); }
    Ok(())
}

/// May a caller write this control?
///
/// `EBUSY` for a grabbed control is the one an application must handle: a
/// control the device pinned while streaming can be written again once the
/// stream stops, which a blanket `EACCES` would not convey.
/// # C: O(log n)
pub fn may_write(handler: &Handler, id: u32) -> Result<(), Errno> {
    let desc = handler.find(id).ok_or(Errno::Einval)?;
    let flags = handler.flags(id).unwrap_or(0);
    if flags & cid::CTRL_FLAG_DISABLED != 0 { return Err(Errno::Einval); }
    if flags & cid::CTRL_FLAG_READ_ONLY != 0 { return Err(Errno::Eacces); }
    if flags & cid::CTRL_FLAG_GRABBED != 0 { return Err(Errno::Ebusy); }
    if desc.is_compound() { return Err(Errno::Einval); }
    Ok(())
}

/// `VIDIOC_G_CTRL`. The 32-bit interface cannot carry a 64-bit control's
/// value, so such a control is only reachable through the extended form.
/// # C: O(log n)
pub fn get_ctrl(handler: &Handler, id: u32) -> Result<i32, Errno> {
    may_read(handler, id)?;
    let desc = handler.find(id).ok_or(Errno::Einval)?;
    if desc.is_64bit() || desc.ctrl_type == cid::CTRL_TYPE_STRING { return Err(Errno::Einval); }
    let value = handler.value(id).ok_or(Errno::Einval)?;
    Ok(value as i32)
}

/// Outcome of a write: the stored value, and whether it differed from what was
/// there. The change bit drives the control event, which must not fire for a
/// write that changed nothing.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Written { pub value: i64, pub changed: bool }

/// Validate and store one control value. # C: O(log n)
pub fn set_value(handler: &Handler, id: u32, value: i64) -> Result<Written, Errno> {
    may_write(handler, id)?;
    let desc = *handler.find(id).ok_or(Errno::Einval)?;
    let settled = validate(desc.ctrl_type, value, desc.minimum, desc.maximum, desc.step)?;
    let previous = handler.store(id, settled).ok_or(Errno::Einval)?;
    // A button has no value; writing it is an action, so it always counts as a
    // change even though the stored word never moves.
    let changed = settled != previous || desc.ctrl_type == cid::CTRL_TYPE_BUTTON;
    Ok(Written { value: settled, changed })
}

/// `VIDIOC_S_CTRL`, whose 32-bit interface excludes the same controls
/// `G_CTRL`'s does. # C: O(log n)
pub fn set_ctrl(handler: &Handler, id: u32, value: i32) -> Result<i32, Errno> {
    let desc = handler.find(id).ok_or(Errno::Einval)?;
    if desc.is_64bit() || desc.ctrl_type == cid::CTRL_TYPE_STRING { return Err(Errno::Einval); }
    Ok(set_value(handler, id, value as i64)?.value as i32)
}

/// One entry of an extended-control request.
#[derive(Copy, Clone, Debug)]
pub struct ExtEntry { pub id: u32, pub size: u32, pub value: i64 }

/// Is `which` a selector this device answers?
///
/// The request selector needs a request descriptor, which nothing here
/// produces yet, so it is refused rather than silently treated as the current
/// value — a caller that asked to read a request's values must not be handed
/// the live ones instead.
/// # C: O(1)
pub fn check_which(which: u32) -> Result<(), Errno> {
    match which {
        cid::CTRL_WHICH_CUR_VAL | cid::CTRL_WHICH_DEF_VAL
        | cid::CTRL_WHICH_MIN_VAL | cid::CTRL_WHICH_MAX_VAL => Ok(()),
        cid::CTRL_WHICH_REQUEST_VAL => Err(Errno::Einval),
        // Any other value is a control class, which selects the whole class;
        // an unrecognised class is `EINVAL`.
        w if w & cid::CTRL_CLASS_MASK == w && w != 0 => Ok(()),
        _ => Err(Errno::Einval),
    }
}

/// Read one entry of a `G_EXT_CTRLS`, honouring the `which` selector: the
/// live value, the declared default, or an end of the range.
/// # C: O(log n)
pub fn get_ext(handler: &Handler, which: u32, id: u32) -> Result<i64, Errno> {
    let desc = *handler.find(id).ok_or(Errno::Einval)?;
    match which {
        cid::CTRL_WHICH_DEF_VAL => Ok(desc.default_value),
        cid::CTRL_WHICH_MIN_VAL => Ok(desc.minimum),
        cid::CTRL_WHICH_MAX_VAL => Ok(desc.maximum),
        _ => { may_read(handler, id)?; handler.value(id).ok_or(Errno::Einval) }
    }
}

/// Validate a whole `S_EXT_CTRLS`/`TRY_EXT_CTRLS` batch without storing
/// anything, reporting the index of the first entry that fails.
///
/// The batch is all-or-nothing: an application setting exposure and gain
/// together must not end up with one applied and the other refused, so
/// validation runs over every entry before the first store.
/// # C: O(entries * log n)
pub fn try_ext(handler: &Handler, which: u32, entries: &[ExtEntry]) -> Result<(), (u32, Errno)> {
    check_which(which).map_err(|e| (0u32, e))?;
    // The read-only selectors describe the control rather than set it, so a
    // write against one is refused before any entry is examined.
    if which == cid::CTRL_WHICH_DEF_VAL || which == cid::CTRL_WHICH_MIN_VAL
        || which == cid::CTRL_WHICH_MAX_VAL {
        return Err((0, Errno::Einval));
    }
    for (index, entry) in entries.iter().enumerate() {
        let index = index as u32;
        let Some(desc) = handler.find(entry.id).copied() else { return Err((index, Errno::Einval)) };
        may_write(handler, entry.id).map_err(|e| (index, e))?;
        validate(desc.ctrl_type, entry.value, desc.minimum, desc.maximum, desc.step)
            .map_err(|e| (index, e))?;
    }
    Ok(())
}

/// Apply a batch that already passed [`try_ext`], returning the ids whose
/// value actually moved so the caller can raise one control event each.
/// # C: O(entries * log n)
pub fn set_ext(handler: &Handler, which: u32, entries: &[ExtEntry])
    -> Result<alloc::vec::Vec<(u32, i64)>, (u32, Errno)>
{
    try_ext(handler, which, entries)?;
    let mut changed = alloc::vec::Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        match set_value(handler, entry.id, entry.value) {
            Ok(w) if w.changed => changed.push((entry.id, w.value)),
            Ok(_) => {}
            Err(e) => return Err((index as u32, e)),
        }
    }
    Ok(changed)
}
