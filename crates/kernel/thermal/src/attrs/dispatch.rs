// Route a class device name to the half of the class that owns it. Both zones
// and cooling devices live in one class directory, distinguished only by their
// name prefix, and every entry point resolves the name against the live
// registry so a retained handle for a departed device reports `ENOENT` rather
// than answering from a copy.

use alloc::string::String;
use alloc::vec::Vec;
use vfs::{KResult, VfsError};

use crate::registry::{cdev_by_name, zone_by_name};

use super::{cdev, zone};

/// Attributes and modes of one class device. # C: O(N_devices)
pub fn attrs(name: &str) -> Option<Vec<(String, u16)>> {
    if let Some(zone) = zone_by_name(name) { return Some(zone::attrs(&zone)); }
    cdev_by_name(name).map(|_| cdev::attrs())
}

/// Symlinks one class device publishes. # C: O(N_bindings)
pub fn links(name: &str) -> Vec<(String, String)> {
    zone_by_name(name).map(|zone| zone::links(&zone)).unwrap_or_default()
}

/// Render one attribute. # C: O(N_trips + N_states²)
pub fn show(name: &str, attr: &str, now_ns: u64) -> KResult<Vec<u8>> {
    if let Some(zone) = zone_by_name(name) { return zone::show(&zone, attr); }
    let cdev = cdev_by_name(name).ok_or(VfsError::Enoent)?;
    cdev::show(&cdev, attr, now_ns)
}

/// Consume one write. # C: O(N_zones)
pub fn store(name: &str, attr: &str, buf: &[u8], now_ns: u64) -> KResult<usize> {
    if let Some(zone) = zone_by_name(name) { return zone::store(&zone, attr, buf); }
    let cdev = cdev_by_name(name).ok_or(VfsError::Enoent)?;
    cdev::store(&cdev, attr, buf, now_ns)
}

/// `uevent` body of one class device. # C: O(1)
pub fn uevent_env(name: &str) -> Option<Vec<String>> {
    if let Some(zone) = zone_by_name(name) { return Some(zone::uevent_env(&zone)); }
    cdev_by_name(name).map(|cdev| cdev::uevent_env(&cdev))
}
