// Turning the addressing attributes of a request into the radio and interface
// it names.
//
// The errno here is the difference between `iw` retrying and `iw` printing a
// misleading error. A request naming a device that does not exist is
// `ENODEV`; a request naming no device at all, where one is required, is
// `EINVAL`; a request naming an interface whose type cannot serve the command
// is `EOPNOTSUPP`.

extern crate alloc;

use alloc::sync::Arc;

use syscall::errno::Errno;

use crate::uapi::attr as a;
use crate::uapi::enums::IfType;
use crate::wdev::Wdev;
use crate::wiphy::{registry, Wiphy};

use super::msg;

/// What a request addressed.
pub struct Target {
    pub wiphy: Arc<Wiphy>,
    /// Interface the request named, when it named one.
    pub wdev: Option<Arc<Wdev>>,
}

/// Resolve the radio a request names, by radio index, interface index or
/// interface identifier — in that order, which is the order a request that
/// carries several of them is read. A request carrying none names no radio.
/// # C: O(N radios × N interfaces)
pub fn wiphy(attrs: &[u8], net_ns: u64) -> Result<Target, Errno> {
    if let Some(index) = msg::get_u32(attrs, a::WIPHY) {
        let w = registry::lookup(index).ok_or(Errno::Enodev)?;
        check_ns(&w, net_ns)?;
        return Ok(Target { wiphy: w, wdev: None });
    }
    if let Some(ifindex) = msg::get_u32(attrs, a::IFINDEX) {
        let (w, d) = registry::lookup_wdev_by_ifindex(ifindex).ok_or(Errno::Enodev)?;
        check_ns(&w, net_ns)?;
        return Ok(Target { wiphy: w, wdev: Some(d) });
    }
    if let Some(id) = msg::get_u64(attrs, a::WDEV) {
        let (w, d) = registry::lookup_wdev(id).ok_or(Errno::Enodev)?;
        check_ns(&w, net_ns)?;
        return Ok(Target { wiphy: w, wdev: Some(d) });
    }
    Err(Errno::Einval)
}

/// Resolve the interface a request names. A command that acts on an interface
/// cannot fall back to a radio: a radio with three interfaces gives no answer
/// to "which one". # C: O(N radios × N interfaces)
pub fn wdev(attrs: &[u8], net_ns: u64) -> Result<(Arc<Wiphy>, Arc<Wdev>), Errno> {
    let t = wiphy(attrs, net_ns)?;
    match t.wdev {
        Some(d) => Ok((t.wiphy, d)),
        None => Err(Errno::Einval),
    }
}

/// Resolve an interface and require it to be one of a set of types.
/// # C: O(N radios × N interfaces)
pub fn wdev_of_type(attrs: &[u8], net_ns: u64, allowed: &[IfType])
    -> Result<(Arc<Wiphy>, Arc<Wdev>), Errno>
{
    let (w, d) = wdev(attrs, net_ns)?;
    if !allowed.contains(&d.iftype()) { return Err(Errno::Eopnotsupp); }
    Ok((w, d))
}

/// Refuse a radio in another network namespace. A radio is not visible from
/// outside the namespace it lives in, and reporting it as absent rather than
/// as forbidden is what keeps the namespace boundary from leaking the fact
/// that it exists. # C: O(1)
fn check_ns(w: &Arc<Wiphy>, net_ns: u64) -> Result<(), Errno> {
    if w.net_ns.load(core::sync::atomic::Ordering::Acquire) == net_ns { Ok(()) }
    else { Err(Errno::Enodev) }
}

/// Whether a request's radio filter, if it has one, selects this radio. A
/// dump with no filter walks every radio. # C: O(N attrs)
pub fn dump_selects(attrs: &[u8], w: &Arc<Wiphy>) -> bool {
    match msg::get_u32(attrs, a::WIPHY) {
        Some(index) => w.index == index,
        None => true,
    }
}
