// The zone half of the class surface.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use kstrtox::{kstrtoint, kstrtoul, BASE_AUTO};
use vfs::{KResult, VfsError};

use crate::governor::available_names;
use crate::uapi::{Mode, TEMP_INVALID};
use crate::zone::ThermalZone;

use super::names;

/// Read-only attribute mode.
pub const RO: u16 = 0o444;
/// Read-write attribute mode.
pub const RW: u16 = 0o644;

/// Attributes and modes a zone publishes. # C: O(N_trips + N_bindings)
pub fn attrs(zone: &Arc<ThermalZone>) -> Vec<(String, u16)> {
    let mut list = alloc::vec![
        (String::from(names::TYPE), RO),
        (String::from(names::TEMP), RO),
        (String::from(names::MODE), RW),
        (String::from(names::POLICY), RW),
        (String::from(names::AVAILABLE_POLICIES), RO),
    ];
    for (index, name) in names::trip_attrs(zone.trip_count()).into_iter().enumerate() {
        // Every third entry is the temperature and the one after it the
        // hysteresis; both are writable only where the provider said so.
        let writable = match index % 3 {
            1 => zone.trip(index / 3).is_some_and(|desc| desc.trip.temp_writable()),
            2 => zone.trip(index / 3).is_some_and(|desc| desc.trip.hyst_writable()),
            _ => false,
        };
        list.push((name, if writable { RW } else { RO }));
    }
    for (id, _, _) in zone.bindings() {
        list.push((names::cdev_attr(id, names::CDEV_TRIP_POINT), RO));
        list.push((names::cdev_attr(id, names::CDEV_WEIGHT), RW));
    }
    list
}

/// `cdev<N>` links, one per binding, pointing at the cooling device's own
/// class directory. # C: O(N_bindings)
pub fn links(zone: &Arc<ThermalZone>) -> Vec<(String, String)> {
    zone.bindings().into_iter()
        .map(|(id, _, cdev)| (names::cdev_link(id), alloc::format!("../{}", cdev.name())))
        .collect()
}

/// Body a `show` returns, with the newline every attribute carries. # C: O(n)
fn line(text: &str) -> Vec<u8> {
    let mut body = String::from(text);
    body.push('\n');
    body.into_bytes()
}

/// Decimal body. # C: O(1)
fn int_line(value: i64) -> Vec<u8> {
    let mut body = String::new();
    let _ = core::fmt::Write::write_fmt(&mut body, format_args!("{value}\n"));
    body.into_bytes()
}

/// Render one zone attribute. # C: O(N_trips)
pub fn show(zone: &Arc<ThermalZone>, attr: &str) -> KResult<Vec<u8>> {
    match attr {
        names::TYPE => Ok(line(zone.ty())),
        names::TEMP => {
            let temp = zone.ops().get_temp().map_err(|_| VfsError::Enodata)?;
            if temp <= TEMP_INVALID { return Err(VfsError::Enodata); }
            Ok(int_line(i64::from(temp)))
        }
        names::MODE => Ok(line(zone.mode().text())),
        names::POLICY => Ok(line(zone.policy())),
        names::AVAILABLE_POLICIES => Ok(available_names().into_bytes()),
        _ => show_indexed(zone, attr),
    }
}

/// Render a per-trip or per-binding attribute. # C: O(N_bindings)
fn show_indexed(zone: &Arc<ThermalZone>, attr: &str) -> KResult<Vec<u8>> {
    if let Some((index, suffix)) = names::parse_trip_attr(attr) {
        let desc = zone.trip(index).ok_or(VfsError::Enoent)?;
        return match suffix {
            names::TRIP_TYPE => Ok(line(desc.trip.ty.text())),
            names::TRIP_TEMP => Ok(int_line(i64::from(desc.trip.temperature))),
            names::TRIP_HYST => Ok(int_line(i64::from(desc.trip.hysteresis))),
            _ => Err(VfsError::Enoent),
        };
    }
    let (id, suffix) = names::parse_cdev_attr(attr).ok_or(VfsError::Enoent)?;
    match suffix {
        names::CDEV_TRIP_POINT => {
            let trip = zone.bindings().into_iter().find(|(bid, _, _)| *bid == id)
                .map(|(_, trip, _)| trip).ok_or(VfsError::Enoent)?;
            Ok(int_line(trip as i64))
        }
        names::CDEV_WEIGHT => {
            let weight = zone.binding_weight(id).ok_or(VfsError::Enoent)?;
            Ok(int_line(i64::from(weight)))
        }
        _ => Err(VfsError::Enoent),
    }
}

/// Consume a write to one zone attribute. # C: O(N_trips)
pub fn store(zone: &Arc<ThermalZone>, attr: &str, buf: &[u8]) -> KResult<usize> {
    match attr {
        names::MODE => {
            let mode = Mode::parse(buf).ok_or(VfsError::Einval)?;
            zone.set_mode(mode);
            crate::registry::notify(&zone.name());
            Ok(buf.len())
        }
        names::POLICY => {
            let text = core::str::from_utf8(buf).map_err(|_| VfsError::Einval)?;
            if !zone.set_policy(text) { return Err(VfsError::Einval); }
            crate::registry::notify(&zone.name());
            Ok(buf.len())
        }
        _ => store_indexed(zone, attr, buf),
    }
}

/// Consume a write to a per-trip or per-binding attribute. # C: O(N_trips)
fn store_indexed(zone: &Arc<ThermalZone>, attr: &str, buf: &[u8]) -> KResult<usize> {
    if let Some((index, suffix)) = names::parse_trip_attr(attr) {
        let value = kstrtoint(buf, BASE_AUTO).map_err(|_| VfsError::Einval)?;
        return match suffix {
            names::TRIP_TEMP => { set_trip_temp(zone, index, value)?; Ok(buf.len()) }
            names::TRIP_HYST => { set_trip_hyst(zone, index, value)?; Ok(buf.len()) }
            _ => Err(VfsError::Eacces),
        };
    }
    let (id, suffix) = names::parse_cdev_attr(attr).ok_or(VfsError::Enoent)?;
    if suffix != names::CDEV_WEIGHT { return Err(VfsError::Eacces); }
    let weight = kstrtoul(buf, BASE_AUTO).map_err(|_| VfsError::Einval)?;
    let weight = u32::try_from(weight).map_err(|_| VfsError::Erange)?;
    if !zone.set_binding_weight(id, weight) { return Err(VfsError::Enoent); }
    Ok(buf.len())
}

/// Move a trip's temperature. A temperature whose hysteresis band would reach
/// below the invalid sentinel is refused: the band bottom is what crossing
/// detection compares against, and one that wraps past the sentinel would
/// make the trip unreleasable. # C: O(N_trips)
pub fn set_trip_temp(zone: &Arc<ThermalZone>, index: usize, temp: i32) -> KResult<()> {
    let mut state = zone.state.lock();
    let desc = state.trips.get_mut(index).ok_or(VfsError::Enoent)?;
    if !desc.trip.temp_writable() { return Err(VfsError::Eacces); }
    if temp == desc.trip.temperature { return Ok(()); }
    if temp != TEMP_INVALID && temp <= TEMP_INVALID.saturating_add(desc.trip.hysteresis) {
        return Err(VfsError::Einval);
    }
    desc.trip.temperature = temp;
    desc.revalidate();
    state.window = None;
    Ok(())
}

/// Move a trip's hysteresis band. # C: O(N_trips)
pub fn set_trip_hyst(zone: &Arc<ThermalZone>, index: usize, hyst: i32) -> KResult<()> {
    if hyst < 0 { return Err(VfsError::Einval); }
    let mut state = zone.state.lock();
    let desc = state.trips.get_mut(index).ok_or(VfsError::Enoent)?;
    if !desc.trip.hyst_writable() { return Err(VfsError::Eacces); }
    if hyst == desc.trip.hysteresis { return Ok(()); }
    if desc.trip.temperature != TEMP_INVALID
        && desc.trip.temperature.saturating_sub(hyst) <= TEMP_INVALID
    {
        return Err(VfsError::Einval);
    }
    desc.trip.hysteresis = hyst;
    state.window = None;
    Ok(())
}

/// `uevent` body for a zone. # C: O(1)
pub fn uevent_env(zone: &Arc<ThermalZone>) -> Vec<String> {
    alloc::vec![
        alloc::format!("DEVTYPE=thermal_zone"),
        alloc::format!("NAME={}", zone.ty()),
        alloc::format!("TEMP={}", zone.temperature()),
    ]
}

#[cfg(test)]
#[path = "../tests/attrs_zone.rs"]
mod tests;
