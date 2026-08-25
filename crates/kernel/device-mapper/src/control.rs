//! Device-mapper control commands over a kernel-owned ioctl byte buffer.
//!
//! User-memory access deliberately does not live here. This module validates
//! the ABI once, then drives the mapper registry and tables using owned bytes;
//! the syscall shim only copies a bounded buffer in and out.

extern crate alloc;

use alloc::sync::Arc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use syscall::errno::Errno;
use sync::{Spinlock, StackedBlock as DmClass};
use vfs::PollSubscribers;

use crate::device::{Geometry, MappedDevice};
use crate::device::registry::{self, BlockResolver};
use crate::target::{DmResult, StatusType};
use crate::table::TableBuilder;
use crate::{types, uapi};

const VERSION: usize = 0;
const DATA_SIZE: usize = 12;
const DATA_START: usize = 16;
const TARGET_COUNT: usize = 20;
const OPEN_COUNT: usize = 24;
const FLAGS: usize = 28;
const EVENT_NR: usize = 32;
const DEV: usize = 40;
const NAME: usize = 48;
const UUID: usize = NAME + uapi::DM_NAME_LEN;
const DATA: usize = uapi::DM_MIN_DATA_SIZE as usize;
const TARGET_SPEC: usize = 40;
const TARGET_SECTOR: usize = 0;
const TARGET_LENGTH: usize = 8;
const TARGET_NEXT: usize = 20;
const TARGET_TYPE: usize = 24;
const MAX_PAYLOAD: usize = (uapi::DM_MAX_TARGETS as usize) * (uapi::DM_MAX_TARGET_PARAMS as usize);

/// A plain character owner exists so opening `/dev/mapper/control` succeeds.
/// The kernel ioctl shim recognizes the exact `(10,236)` node and invokes
/// [`dispatch`], preserving the same route for a node recreated with mknod.
pub struct ControlCharOps;
static GLOBAL_EVENT_NR: AtomicU64 = AtomicU64::new(0);
static GLOBAL_EVENTQ: Spinlock<Option<Arc<PollSubscribers>>, DmClass> = Spinlock::new(None);

fn global_eventq() -> Arc<PollSubscribers> {
    let mut q = GLOBAL_EVENTQ.lock();
    q.get_or_insert_with(|| Arc::new(PollSubscribers::new())).clone()
}

/// Publish one control-plane event to every open control-file description.
/// Linux's `dm_global_event_nr` and `dm_global_eventq` are global to the
/// control file, not to one mapped device. # C: O(subscribers)
pub fn notify_global_event() {
    GLOBAL_EVENT_NR.fetch_add(1, Ordering::AcqRel);
    global_eventq().notify();
}

/// Arm one control-file description at the current global event number. This
/// is the owner-side equivalent of Linux `DM_DEV_ARM_POLL`. # C: O(1)
pub fn arm_poll_file(file: &vfs::File) {
    file.set_private_data(GLOBAL_EVENT_NR.load(Ordering::Acquire));
}

impl vfs::CharDevOps for ControlCharOps {
    fn open_file(&self, _devt: vfs::Devt, file: &vfs::File) -> vfs::KResult<()> {
        arm_poll_file(file);
        Ok(())
    }

    fn poll_file(&self, _devt: vfs::Devt, file: &vfs::File) -> vfs::KResult<u32> {
        Ok(if GLOBAL_EVENT_NR.load(Ordering::Acquire) != file.private_data() {
            vfs::POLL_IN
        } else { 0 })
    }

    fn poll_subscribers_file(&self, _devt: vfs::Devt, _file: &vfs::File) -> Option<Arc<PollSubscribers>> {
        Some(global_eventq())
    }

    fn can_poll(&self, _devt: vfs::Devt) -> bool { true }
}

#[derive(Copy, Clone)]
struct Header {
    data_size: usize,
    data_start: usize,
    target_count: u32,
    flags: u32,
    event_nr: u32,
    dev: u64,
}

impl Header {
    fn read(bytes: &[u8]) -> DmResult<Self> {
        if bytes.len() < DATA { return Err(Errno::Einval); }
        let data_size = usize::try_from(read_u32(bytes, DATA_SIZE)?).map_err(|_| Errno::Einval)?;
        if !(DATA..=MAX_PAYLOAD).contains(&data_size) || data_size > bytes.len() { return Err(Errno::Einval); }
        Ok(Self {
            data_size,
            data_start: usize::try_from(read_u32(bytes, DATA_START)?).map_err(|_| Errno::Einval)?,
            target_count: read_u32(bytes, TARGET_COUNT)?,
            flags: read_u32(bytes, FLAGS)?,
            event_nr: read_u32(bytes, EVENT_NR)?,
            dev: read_u64(bytes, DEV)?,
        })
    }

    fn stamp_reply(self, bytes: &mut [u8]) -> DmResult<()> {
        put_u32(bytes, VERSION, uapi::DM_VERSION_MAJOR)?;
        put_u32(bytes, VERSION + 4, uapi::DM_VERSION_MINOR)?;
        put_u32(bytes, VERSION + 8, uapi::DM_VERSION_PATCHLEVEL)?;
        put_u32(bytes, FLAGS, self.flags & !uapi::CLEARED_ON_ENTRY_FLAGS)?;
        Ok(())
    }
}

mod commands;
use commands::{
    dev_create, dev_rename, dev_suspend, dev_wait, list_devices, list_versions,
    set_geometry, table_deps, table_load, table_status, target_msg,
};

/// Dispatch one device-mapper control request. `bytes` must contain the exact
/// input `data_size` copied from userspace; every successful reply is written
/// back into that same bounded storage. # C: O(command payload + targets)
pub fn dispatch(request: u32, bytes: &mut [u8]) -> DmResult<()> {
    if uapi::cmd_type(request) != uapi::DM_IOCTL { return Err(Errno::Enotty); }
    let cmd = uapi::cmd_nr(request);
    if cmd > uapi::DM_CMD_LAST { return Err(Errno::Enotty); }
    let header = Header::read(bytes)?;
    header.stamp_reply(bytes)?;
    if cmd == uapi::DM_VERSION_CMD { return Ok(()); }
    types::register_builtin();
    match cmd {
        uapi::DM_REMOVE_ALL_CMD => { registry::remove_all(false); clear_output(bytes)?; }
        uapi::DM_LIST_DEVICES_CMD => list_devices(bytes)?,
        uapi::DM_DEV_CREATE_CMD => dev_create(header, bytes)?,
        uapi::DM_DEV_REMOVE_CMD => {
            let dev = device_of(header, bytes)?;
            registry::remove(&dev, header.flags & uapi::DM_DEFERRED_REMOVE != 0)?;
        }
        uapi::DM_DEV_RENAME_CMD => dev_rename(header, bytes)?,
        uapi::DM_DEV_SUSPEND_CMD => dev_suspend(header, bytes)?,
        uapi::DM_DEV_STATUS_CMD => { let dev = device_of(header, bytes)?; fill_status(bytes, &dev); }
        uapi::DM_DEV_WAIT_CMD => dev_wait(header, bytes)?,
        uapi::DM_TABLE_LOAD_CMD => table_load(header, bytes)?,
        uapi::DM_TABLE_CLEAR_CMD => { let dev = device_of(header, bytes)?; dev.clear_table(); fill_status(bytes, &dev); }
        uapi::DM_TABLE_DEPS_CMD => table_deps(header, bytes)?,
        uapi::DM_TABLE_STATUS_CMD => table_status(header, bytes)?,
        uapi::DM_LIST_VERSIONS_CMD => list_versions(bytes, None)?,
        uapi::DM_TARGET_MSG_CMD => target_msg(header, bytes)?,
        uapi::DM_DEV_SET_GEOMETRY_CMD => set_geometry(header, bytes)?,
        uapi::DM_DEV_ARM_POLL_CMD => { let dev = device_of(header, bytes)?; fill_status(bytes, &dev); }
        uapi::DM_GET_TARGET_VERSION_CMD => {
            let name = fixed_cstr(bytes, NAME, uapi::DM_NAME_LEN)?.to_string();
            list_versions(bytes, Some(&name))?
        }
        _ => return Err(Errno::Enotty),
    }
    Ok(())
}


fn device_of(header: Header, bytes: &[u8]) -> DmResult<alloc::sync::Arc<MappedDevice>> {
    let name = fixed_cstr(bytes, NAME, uapi::DM_NAME_LEN)?;
    let uuid = fixed_cstr(bytes, UUID, uapi::DM_UUID_LEN)?;
    registry::find(registry::key_of(name, uuid, header.dev)?)
}

fn fill_status(bytes: &mut [u8], dev: &MappedDevice) {
    let mut flags = read_u32(bytes, FLAGS).unwrap_or(0) & !uapi::CLEARED_ON_ENTRY_FLAGS;
    if dev.suspended() { flags |= uapi::DM_SUSPEND_FLAG; }
    if dev.live_table().is_some() { flags |= uapi::DM_ACTIVE_PRESENT_FLAG; }
    if dev.inactive_table().is_some() { flags |= uapi::DM_INACTIVE_PRESENT_FLAG; }
    let _ = put_u32(bytes, FLAGS, flags);
    let _ = put_u32(bytes, OPEN_COUNT, registry::opener_count(dev));
    let _ = put_u32(bytes, EVENT_NR, dev.event_nr());
    let _ = put_u64(bytes, DEV, registry::devt_of(dev));
    let _ = write_fixed(bytes, NAME, uapi::DM_NAME_LEN, &dev.name());
    if let Some(uuid) = dev.uuid() { let _ = write_fixed(bytes, UUID, uapi::DM_UUID_LEN, &uuid); }
}

fn clear_output(bytes: &mut [u8]) -> DmResult<()> {
    put_u32(bytes, TARGET_COUNT, 0)?;
    put_u32(bytes, DATA_START, uapi::DM_MIN_DATA_SIZE)?;
    put_u32(bytes, DATA_SIZE, uapi::DM_MIN_DATA_SIZE)
}

fn write_payload(bytes: &mut [u8], payload: &[u8]) -> DmResult<()> {
    let capacity = Header::read(bytes)?.data_size;
    clear_output(bytes)?;
    let writable = capacity.saturating_sub(DATA);
    let copied = payload.len().min(writable);
    bytes[DATA..DATA + copied].copy_from_slice(&payload[..copied]);
    put_u32(bytes, DATA_SIZE, u32::try_from(DATA + copied).map_err(|_| Errno::Einval)?)?;
    if copied != payload.len() {
        let flags = read_u32(bytes, FLAGS)? | uapi::DM_BUFFER_FULL_FLAG;
        put_u32(bytes, FLAGS, flags)?;
    }
    Ok(())
}

fn fixed_cstr<'a>(bytes: &'a [u8], at: usize, len: usize) -> DmResult<&'a str> {
    let end = at.checked_add(len).ok_or(Errno::Einval)?;
    let slice = bytes.get(at..end).ok_or(Errno::Einval)?;
    let nul = slice.iter().position(|b| *b == 0).unwrap_or(slice.len());
    core::str::from_utf8(&slice[..nul]).map_err(|_| Errno::Einval)
}

fn variable_cstr(bytes: &[u8], at: usize, end: usize) -> DmResult<&str> {
    if at < DATA || at >= end || end > bytes.len() { return Err(Errno::Einval); }
    let tail = &bytes[at..end];
    let nul = tail.iter().position(|b| *b == 0).ok_or(Errno::Einval)?;
    core::str::from_utf8(&tail[..nul]).map_err(|_| Errno::Einval)
}

fn write_fixed(bytes: &mut [u8], at: usize, len: usize, value: &str) -> DmResult<()> {
    if value.len() >= len { return Err(Errno::Einval); }
    let end = at.checked_add(len).ok_or(Errno::Einval)?;
    let dst = bytes.get_mut(at..end).ok_or(Errno::Einval)?;
    dst.fill(0);
    dst[..value.len()].copy_from_slice(value.as_bytes());
    Ok(())
}

fn read_u32(bytes: &[u8], at: usize) -> DmResult<u32> {
    let raw: [u8; 4] = bytes.get(at..at + 4).ok_or(Errno::Einval)?.try_into().map_err(|_| Errno::Einval)?;
    Ok(u32::from_le_bytes(raw))
}
fn read_u64(bytes: &[u8], at: usize) -> DmResult<u64> {
    let raw: [u8; 8] = bytes.get(at..at + 8).ok_or(Errno::Einval)?.try_into().map_err(|_| Errno::Einval)?;
    Ok(u64::from_le_bytes(raw))
}
fn put_u32(bytes: &mut [u8], at: usize, value: u32) -> DmResult<()> {
    let dst = bytes.get_mut(at..at + 4).ok_or(Errno::Einval)?;
    dst.copy_from_slice(&value.to_le_bytes());
    Ok(())
}
fn put_u64(bytes: &mut [u8], at: usize, value: u64) -> DmResult<()> {
    let dst = bytes.get_mut(at..at + 8).ok_or(Errno::Einval)?;
    dst.copy_from_slice(&value.to_le_bytes());
    Ok(())
}
fn push_u32(out: &mut Vec<u8>, value: u32) { out.extend_from_slice(&value.to_le_bytes()); }
fn push_u64(out: &mut Vec<u8>, value: u64) { out.extend_from_slice(&value.to_le_bytes()); }

#[cfg(test)]
#[path = "control/tests/control.rs"]
mod tests;
