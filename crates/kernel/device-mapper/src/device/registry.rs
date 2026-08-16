//! Which mapped devices exist, and the three keys they answer to.
//!
//! A device is reachable by name, by uuid, or by device number, and every
//! lookup goes through here. The name is mutable and the uuid is settable
//! exactly once — a uuid that could be re-pointed would silently redirect
//! every tool that had already resolved a volume through it.

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Spinlock, StackedBlock as DmClass};
use syscall::errno::Errno;

use super::{MappedDevice, DM_MAJOR};
use crate::target::DmResult;
use crate::uapi::DM_CONTROL_NODE;

struct Cell { dev: Arc<MappedDevice> }

static CELLS: Spinlock<Vec<Cell>, DmClass> = Spinlock::new(Vec::new());

/// Refuse a device name that cannot become a `/dev/mapper` entry. A slash
/// would name a different directory, `.` and `..` name the directory itself
/// and its parent, and the control node's own name would shadow the node every
/// one of these commands arrives on. # C: O(name)
pub fn check_name(name: &str) -> DmResult<()> {
    if name.is_empty() || name.contains('/') { return Err(Errno::Einval); }
    if name == DM_CONTROL_NODE || name == "." || name == ".." { return Err(Errno::Einval); }
    if name.len() >= crate::uapi::DM_NAME_LEN { return Err(Errno::Einval); }
    Ok(())
}

/// Create and publish a device. `minor` selects a specific number; `None`
/// takes the lowest free one. # C: O(N_devices)
pub fn create(name: &str, uuid: Option<&str>, minor: Option<u32>) -> DmResult<Arc<MappedDevice>> {
    check_name(name)?;
    if let Some(u) = uuid {
        if u.len() >= crate::uapi::DM_UUID_LEN { return Err(Errno::Einval); }
    }
    let mut cells = CELLS.lock();
    if cells.iter().any(|c| c.dev.name() == name) { return Err(Errno::Ebusy); }
    if let Some(u) = uuid {
        if cells.iter().any(|c| c.dev.uuid().as_deref() == Some(u)) { return Err(Errno::Ebusy); }
    }
    let minor = match minor {
        Some(m) => {
            if cells.iter().any(|c| c.dev.minor == m) { return Err(Errno::Ebusy); }
            m
        }
        None => (0u32..).find(|m| !cells.iter().any(|c| c.dev.minor == *m)).ok_or(Errno::Enospc)?,
    };
    let dev = MappedDevice::new(minor, name, uuid);
    cells.push(Cell { dev: dev.clone() });
    Ok(dev)
}

/// Look up by name. # C: O(N_devices)
pub fn by_name(name: &str) -> Option<Arc<MappedDevice>> {
    CELLS.lock().iter().find(|c| c.dev.name() == name).map(|c| c.dev.clone())
}

/// Look up by uuid. # C: O(N_devices)
pub fn by_uuid(uuid: &str) -> Option<Arc<MappedDevice>> {
    CELLS.lock().iter().find(|c| c.dev.uuid().as_deref() == Some(uuid)).map(|c| c.dev.clone())
}

/// Look up by minor. # C: O(N_devices)
pub fn by_minor(minor: u32) -> Option<Arc<MappedDevice>> {
    CELLS.lock().iter().find(|c| c.dev.minor == minor).map(|c| c.dev.clone())
}

/// Every device, in creation order. # C: O(N_devices)
pub fn list() -> Vec<Arc<MappedDevice>> {
    CELLS.lock().iter().map(|c| c.dev.clone()).collect()
}

/// How a command named the device it wants to act on.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Key<'a> {
    /// By uuid, which outranks a name when both are present.
    Uuid(&'a str),
    /// By name.
    Name(&'a str),
    /// By packed device number.
    Dev(u64),
}

/// Choose the key a request carries. Supplying both a name and a uuid is
/// refused rather than resolved by preference: the two could name different
/// devices, and acting on either would be a guess.
/// # C: O(1)
pub fn key_of<'a>(name: &'a str, uuid: &'a str, dev: u64) -> DmResult<Key<'a>> {
    match (!uuid.is_empty(), !name.is_empty(), dev != 0) {
        (true, false, _) => Ok(Key::Uuid(uuid)),
        (false, true, _) => Ok(Key::Name(name)),
        (false, false, true) => Ok(Key::Dev(dev)),
        _ => Err(Errno::Einval),
    }
}

/// Resolve a key to a device. # C: O(N_devices)
pub fn find(key: Key<'_>) -> DmResult<Arc<MappedDevice>> {
    let found = match key {
        Key::Uuid(u) => by_uuid(u),
        Key::Name(n) => by_name(n),
        Key::Dev(d) => {
            let kdev = vfs::new_decode_dev(d as u32);
            if vfs::kdev_major(kdev) != DM_MAJOR { None } else { by_minor(vfs::kdev_minor(kdev)) }
        }
    };
    found.ok_or(Errno::Enxio)
}

/// Rename a device, or set its uuid when `as_uuid`. # C: O(N_devices)
pub fn rename(dev: &Arc<MappedDevice>, new: &str, as_uuid: bool) -> DmResult<()> {
    if as_uuid {
        if new.len() >= crate::uapi::DM_UUID_LEN { return Err(Errno::Einval); }
        let cells = CELLS.lock();
        if cells.iter().any(|c| c.dev.uuid().as_deref() == Some(new)) { return Err(Errno::Ebusy); }
        drop(cells);
        return dev.set_uuid(new);
    }
    check_name(new)?;
    let cells = CELLS.lock();
    if cells.iter().any(|c| c.dev.name() == new && !Arc::ptr_eq(&c.dev, dev)) { return Err(Errno::Ebusy); }
    drop(cells);
    dev.set_name(new);
    Ok(())
}

/// Withdraw a device. An open device is refused unless the caller asked for
/// the removal to happen at last close, which is reported as success because
/// the request was accepted. # C: O(N_devices)
pub fn remove(dev: &Arc<MappedDevice>, deferred: bool) -> DmResult<()> {
    if dev.open_count() != 0 {
        if !deferred { return Err(Errno::Ebusy); }
        dev.with_state(|s| s.flags |= crate::suspend::DmFlags::DEFERRED_REMOVE);
        return Ok(());
    }
    dev.with_state(|s| s.flags |= crate::suspend::DmFlags::DELETING | crate::suspend::DmFlags::FREEING);
    CELLS.lock().retain(|c| !Arc::ptr_eq(&c.dev, dev));
    Ok(())
}

/// Withdraw every device that can be withdrawn, restarting the walk after each
/// one: removing a stacked device can remove the devices below it, so no
/// iterator over the list survives a removal. # C: O(N_devices^2)
pub fn remove_all(keep_open: bool) {
    loop {
        let victim = CELLS.lock().iter()
            .find(|c| !keep_open || c.dev.open_count() == 0)
            .map(|c| c.dev.clone());
        let Some(dev) = victim else { return };
        if remove(&dev, false).is_err() {
            CELLS.lock().retain(|c| !Arc::ptr_eq(&c.dev, &dev));
        }
    }
}

/// Drop every device without regard to state. Exists so a hosted test starts
/// from an empty registry whatever ran before it. # C: O(N_devices)
pub fn reset_for_test() { CELLS.lock().clear(); }

/// Name a device number prints as in a dependency report. # C: O(1)
pub fn devt_of(dev: &MappedDevice) -> u64 { vfs::huge_encode_dev(vfs::mkdev(DM_MAJOR, dev.minor)) }

/// `/dev/mapper/<name>` for a device. # C: O(name)
pub fn node_path(dev: &MappedDevice) -> String {
    let mut p = String::from("/dev/");
    p.push_str(crate::uapi::DM_DIR);
    p.push('/');
    p.push_str(&dev.name().to_string());
    p
}
