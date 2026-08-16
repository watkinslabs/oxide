//! Enumerating controls: `QUERYCTRL`, `QUERY_EXT_CTRL` and `QUERYMENU`.

use syscall::errno::Errno;

use crate::uapi::ctrl_ids as cid;
use super::desc::{ControlDesc, Handler};

/// Which controls a walk admits.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Want { Any, Compound, Simple }

/// Resolve a query id to a control.
///
/// Without a walk flag the id must name a control exactly. With one, the
/// answer is the next control above it — which is how an application
/// enumerates a device it knows nothing about, starting from zero and walking
/// until the call fails. Either way, failure is `EINVAL`: there is no separate
/// "no such control" errno on this path, and a program that expects one will
/// mis-handle a device with a sparse id space.
/// # C: O(log n) exact, O(n) walking
pub fn find(handler: &Handler, query_id: u32) -> Result<&ControlDesc, Errno> {
    let walking = query_id & cid::CTRL_QUERY_FLAGS;
    let id = query_id & !cid::CTRL_QUERY_FLAGS;
    if walking == 0 {
        return handler.find(id).ok_or(Errno::Einval);
    }
    let want = match walking {
        w if w == cid::CTRL_QUERY_FLAGS => Want::Any,
        w if w == cid::CTRL_FLAG_NEXT_COMPOUND => Want::Compound,
        _ => Want::Simple,
    };
    handler.descs().iter()
        .filter(|d| d.id > id)
        .find(|d| match want {
            Want::Any => true,
            Want::Compound => d.is_compound(),
            Want::Simple => !d.is_compound(),
        })
        .ok_or(Errno::Einval)
}

/// A control's description in the legacy 32-bit `v4l2_queryctrl` shape.
///
/// The legacy structure cannot describe a compound control or a 64-bit range,
/// so the reference refuses rather than truncating: a value silently cut to 32
/// bits would have an application negotiating against a range the device does
/// not have.
/// # C: O(1)
pub fn legacy_view(desc: &ControlDesc, flags: u32) -> Result<(i32, i32, i32, i32), Errno> {
    if desc.is_compound() || flags & cid::CTRL_FLAG_HAS_PAYLOAD != 0 {
        return Err(Errno::Einval);
    }
    let fits = |v: i64| -> Result<i32, Errno> {
        if v < i32::MIN as i64 || v > i32::MAX as i64 { Err(Errno::Einval) } else { Ok(v as i32) }
    };
    let step = if desc.step > i32::MAX as u64 { return Err(Errno::Einval) } else { desc.step as i32 };
    Ok((fits(desc.minimum)?, fits(desc.maximum)?, step, fits(desc.default_value)?))
}

/// One menu entry, as `QUERYMENU` reports it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MenuEntry {
    /// A named entry of a plain menu.
    Name(&'static str),
    /// A numeric entry of an integer menu.
    Value(i64),
}

/// `VIDIOC_QUERYMENU`.
///
/// Every refusal here is `EINVAL` — the control is not a menu, the index is
/// outside the range, the driver marked the entry unusable, or the entry has
/// no name. An application enumerating a menu walks the index upward until one
/// of those fires, so the answer being uniformly `EINVAL` is what terminates
/// the loop.
/// # C: O(log n)
pub fn query_menu(handler: &Handler, id: u32, index: u32) -> Result<MenuEntry, Errno> {
    let desc = handler.find(id).ok_or(Errno::Einval)?;
    if desc.ctrl_type != cid::CTRL_TYPE_MENU && desc.ctrl_type != cid::CTRL_TYPE_INTEGER_MENU {
        return Err(Errno::Einval);
    }
    let index64 = index as i64;
    if index64 < desc.minimum || index64 > desc.maximum { return Err(Errno::Einval); }
    if index64 < 64 && desc.step & (1u64 << index64) != 0 { return Err(Errno::Einval); }
    let slot = index as usize;
    if desc.ctrl_type == cid::CTRL_TYPE_INTEGER_MENU {
        return desc.menu_values.get(slot).copied().map(MenuEntry::Value).ok_or(Errno::Einval);
    }
    match desc.menu.get(slot) {
        Some(name) if !name.is_empty() => Ok(MenuEntry::Name(name)),
        _ => Err(Errno::Einval),
    }
}
