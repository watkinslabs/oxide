//! Which mapped devices exist, and the three keys they answer to.
//!
//! A device is reachable by name, by uuid, or by device number, and every
//! lookup goes through here. The name is mutable and the uuid is settable
//! exactly once — a uuid that could be re-pointed would silently redirect
//! every tool that had already resolved a volume through it.

extern crate alloc;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Spinlock, StackedBlock as DmClass};
use syscall::errno::Errno;

use super::{MappedDevice, DM_MAJOR};
use crate::target::{DevMode, DeviceResolver, DmDev, DmResult};
use crate::uapi::DM_CONTROL_NODE;

/// Fixed-major mapper disks allocate their exact ABI minor. They neither own
/// partition children nor reserve a 16-minor whole-disk window.
pub const DM_BLOCK_DRIVER: block::registry::BlockDriver =
    block::registry::BlockDriver::unpartitioned_fixed("device-mapper", DM_MAJOR);

struct Cell {
    dev: Arc<MappedDevice>,
    /// Internal block-registry identity. `/dev/mapper/<name>` is the node,
    /// but `dm-N` stays stable while users rename the mapper device.
    disk_name: String,
    /// A creation reservation is invisible until its block node is published.
    published: bool,
}

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
    let (dev, disk_name) = {
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
    let disk_name = disk_name(minor);
    cells.push(Cell { dev: dev.clone(), disk_name: disk_name.clone(), published: false });
    (dev, disk_name)
    };
    // Block registration owns both the major/minor reservation and the VFS
    // block-device bridge. A failed publication withdraws the private
    // reservation so another create gets a clean retry.
    let index = block::registry::register_with_driver_at(
        DM_BLOCK_DRIVER, &disk_name, &node_name(name), None, Some(dev.minor),
        dev.clone() as Arc<dyn block::BlockDevice>);
    if index == 0 {
        CELLS.lock().retain(|c| !Arc::ptr_eq(&c.dev, &dev));
        return Err(Errno::Ebusy);
    }
    if let Some(cell) = CELLS.lock().iter_mut().find(|c| Arc::ptr_eq(&c.dev, &dev)) {
        cell.published = true;
    } else {
        // The reservation cannot be removed by a normal command, but do not
        // leave a block node behind if an internal caller reset the registry.
        let _ = block::registry::unregister(&disk_name);
        return Err(Errno::Ebusy);
    }
    Ok(dev)
}

/// Look up by name. # C: O(N_devices)
pub fn by_name(name: &str) -> Option<Arc<MappedDevice>> {
    CELLS.lock().iter().find(|c| c.published && c.dev.name() == name).map(|c| c.dev.clone())
}

/// Look up by uuid. # C: O(N_devices)
pub fn by_uuid(uuid: &str) -> Option<Arc<MappedDevice>> {
    CELLS.lock().iter().find(|c| c.published && c.dev.uuid().as_deref() == Some(uuid)).map(|c| c.dev.clone())
}

/// Look up by minor. # C: O(N_devices)
pub fn by_minor(minor: u32) -> Option<Arc<MappedDevice>> {
    CELLS.lock().iter().find(|c| c.published && c.dev.minor == minor).map(|c| c.dev.clone())
}

/// Every device, in creation order. # C: O(N_devices)
pub fn list() -> Vec<Arc<MappedDevice>> {
    CELLS.lock().iter().filter(|c| c.published).map(|c| c.dev.clone()).collect()
}

/// Actual VFS opener count for a mapper block node. The block registry owns
/// this count because it admits and releases file descriptions; the mapped
/// device's internal counter is not a second, divergent source of truth.
/// # C: O(N_devices + N_disks)
pub fn opener_count(dev: &MappedDevice) -> u32 {
    let disk_name = CELLS.lock().iter().find(|c| c.published && c.dev.minor == dev.minor)
        .map(|c| c.disk_name.clone());
    disk_name.and_then(|name| block::registry::opener_count(&name)).unwrap_or(0)
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
    let disk_name = {
        let cells = CELLS.lock();
        if cells.iter().any(|c| c.published && c.dev.name() == new && !Arc::ptr_eq(&c.dev, dev)) { return Err(Errno::Ebusy); }
        cells.iter().find(|c| c.published && Arc::ptr_eq(&c.dev, dev))
            .map(|c| c.disk_name.clone()).ok_or(Errno::Enxio)?
    };
    if !block::registry::republish_node(&disk_name, &node_name(new)) { return Err(Errno::Ebusy); }
    dev.set_name(new);
    Ok(())
}

/// Withdraw a device. An open device is refused unless the caller asked for
/// the removal to happen at last close, which is reported as success because
/// the request was accepted. # C: O(N_devices)
pub fn remove(dev: &Arc<MappedDevice>, deferred: bool) -> DmResult<()> {
    let disk_name = CELLS.lock().iter().find(|c| c.published && Arc::ptr_eq(&c.dev, dev))
        .map(|c| c.disk_name.clone()).ok_or(Errno::Enxio)?;
    if block::registry::opener_count(&disk_name).unwrap_or(0) != 0 {
        if !deferred { return Err(Errno::Ebusy); }
        dev.with_state(|s| s.flags |= crate::suspend::DmFlags::DEFERRED_REMOVE);
        return Ok(());
    }
    if !block::registry::unregister(&disk_name) { return Err(Errno::Ebusy); }
    dev.with_state(|s| s.flags |= crate::suspend::DmFlags::DELETING | crate::suspend::DmFlags::FREEING);
    CELLS.lock().retain(|c| !Arc::ptr_eq(&c.dev, dev));
    Ok(())
}

/// Withdraw every device that can be withdrawn, restarting the walk after each
/// one: removing a stacked device can remove the devices below it, so no
/// iterator over the list survives a removal. # C: O(N_devices^2)
pub fn remove_all(keep_open: bool) {
    loop {
        let victim = CELLS.lock().iter().filter(|c| c.published)
            .find(|c| !keep_open || block::registry::opener_count(&c.disk_name).unwrap_or(0) == 0)
            .map(|c| c.dev.clone());
        let Some(dev) = victim else { return };
        // A concurrent open can close the block lifecycle gate after this
        // scan. Preserve the mapper cell in that case: dropping only its
        // private index would strand a live published block node.
        if remove(&dev, false).is_err() { return; }
    }
}

/// Drop every device without regard to state. Exists so a hosted test starts
/// from an empty registry whatever ran before it. # C: O(N_devices)
pub fn reset_for_test() {
    let names: Vec<String> = CELLS.lock().iter().map(|c| c.disk_name.clone()).collect();
    for name in names { let _ = block::registry::unregister(&name); }
    CELLS.lock().clear();
}

/// Name a device number prints as in a dependency report. # C: O(1)
pub fn devt_of(dev: &MappedDevice) -> u64 { vfs::huge_encode_dev(vfs::mkdev(DM_MAJOR, dev.minor)) }

/// `/dev/mapper/<name>` for a device. # C: O(name)
pub fn node_path(dev: &MappedDevice) -> String {
    format!("/dev/{}", node_name(&dev.name()))
}

/// Stable internal block-registry name for a mapper minor. # C: O(output)
pub fn disk_name(minor: u32) -> String { format!("dm-{minor}") }

/// Devtmpfs-relative mapper node path. # C: O(output)
pub fn node_name(name: &str) -> String { format!("{}/{}", crate::uapi::DM_DIR, name) }

/// Resolver supplied to target constructors. It accepts Linux's `major:minor`
/// form plus ordinary `/dev/<name>` and `/dev/mapper/<name>` paths, then
/// returns the registry-owned coherent block handle.
pub struct BlockResolver;

impl DeviceResolver for BlockResolver {
    fn get_device(&self, path: &str, mode: DevMode) -> DmResult<DmDev> {
        let disk = if let Some((major, minor)) = crate::args::parse_devt(path) {
            block::registry::by_dev(block::registry::encode_dev(major, minor))
        } else if let Some(name) = path.strip_prefix("/dev/") {
            if let Some(mapper_name) = name.strip_prefix("mapper/") {
                let map = by_name(mapper_name).ok_or(Errno::Enxio)?;
                block::registry::by_name(&disk_name(map.minor))
            } else {
                block::registry::by_name(name)
            }
        } else {
            block::registry::by_name(path)
        };
        let disk = disk.ok_or(Errno::Enxio)?;
        Ok(DmDev {
            major: disk.number.major,
            minor: disk.number.minor,
            name: path.to_string(),
            mode,
            bdev: disk.dev.clone(),
        })
    }
}
