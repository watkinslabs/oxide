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

fn dev_create(header: Header, bytes: &mut [u8]) -> DmResult<()> {
    let name = fixed_cstr(bytes, NAME, uapi::DM_NAME_LEN)?;
    if name.is_empty() { return Err(Errno::Einval); }
    let uuid = fixed_cstr(bytes, UUID, uapi::DM_UUID_LEN)?;
    let minor = if header.flags & uapi::DM_PERSISTENT_DEV_FLAG != 0 {
        let kdev = vfs::new_decode_dev(header.dev as u32);
        if vfs::kdev_major(kdev) != crate::device::DM_MAJOR { return Err(Errno::Einval); }
        Some(vfs::kdev_minor(kdev))
    } else { None };
    let dev = registry::create(name, (!uuid.is_empty()).then_some(uuid), minor)?;
    fill_status(bytes, &dev);
    Ok(())
}

fn dev_rename(header: Header, bytes: &mut [u8]) -> DmResult<()> {
    let new_value = variable_cstr(bytes, header.data_start, header.data_size)?.to_string();
    if new_value.is_empty() { return Err(Errno::Einval); }
    let dev = device_of(header, bytes)?;
    registry::rename(&dev, &new_value, header.flags & uapi::DM_UUID_FLAG != 0)?;
    fill_status(bytes, &dev);
    Ok(())
}

fn dev_suspend(header: Header, bytes: &mut [u8]) -> DmResult<()> {
    let lockfs = header.flags & uapi::DM_SKIP_LOCKFS_FLAG == 0;
    let noflush = header.flags & uapi::DM_NOFLUSH_FLAG != 0;
    let dev = device_of(header, bytes)?;
    if header.flags & uapi::DM_SUSPEND_FLAG != 0 { dev.suspend(lockfs, noflush)?; }
    else { dev.resume(lockfs, noflush)?; }
    fill_status(bytes, &dev);
    Ok(())
}

fn dev_wait(header: Header, bytes: &mut [u8]) -> DmResult<()> {
    let dev = device_of(header, bytes)?;
    if dev.event_nr() == header.event_nr {
        #[cfg(target_os = "oxide-kernel")]
        {
            // SAFETY: this is process context, the device predicate is read
            // without holding the device lock across schedule, and
            // bump_event publishes the counter before waking this list.
            unsafe {
                let _ = sched::live::wait_event_uninterruptible(
                    dev.event_waiters(), || dev.event_nr() != header.event_nr,
                );
            }
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        return Err(Errno::Eagain);
    }
    fill_status(bytes, &dev);
    Ok(())
}

fn table_load(header: Header, bytes: &mut [u8]) -> DmResult<()> {
    if header.target_count == 0 || header.target_count > uapi::DM_MAX_TARGETS { return Err(Errno::Einval); }
    if header.data_start < DATA || header.data_start >= header.data_size { return Err(Errno::Einval); }
    let mut cursor = header.data_start;
    let resolver = BlockResolver;
    let mut builder = TableBuilder::new(header.flags & uapi::DM_READONLY_FLAG == 0);
    for number in 0..header.target_count {
        let spec_end = cursor.checked_add(TARGET_SPEC).ok_or(Errno::Einval)?;
        if spec_end > header.data_size { return Err(Errno::Einval); }
        let begin = read_u64(bytes, cursor + TARGET_SECTOR)?;
        let len = read_u64(bytes, cursor + TARGET_LENGTH)?;
        let next = usize::try_from(read_u32(bytes, cursor + TARGET_NEXT)?).map_err(|_| Errno::Einval)?;
        let type_name = fixed_cstr(bytes, cursor + TARGET_TYPE, uapi::DM_MAX_TYPE_NAME)?;
        let params = variable_cstr(bytes, spec_end, header.data_size)?;
        let target = types::get(type_name).ok_or(Errno::Einval)?;
        builder.add_target(&target, begin, len, params, &resolver)?;
        if number + 1 != header.target_count {
            if next < TARGET_SPEC || next & 7 != 0 { return Err(Errno::Einval); }
            cursor = cursor.checked_add(next).ok_or(Errno::Einval)?;
            if cursor >= header.data_size { return Err(Errno::Einval); }
        }
    }
    let dev = device_of(header, bytes)?;
    dev.load_table(alloc::sync::Arc::new(builder.complete()));
    fill_status(bytes, &dev);
    Ok(())
}

fn table_deps(header: Header, bytes: &mut [u8]) -> DmResult<()> {
    let dev = device_of(header, bytes)?;
    let inactive = header.flags & uapi::DM_QUERY_INACTIVE_TABLE_FLAG != 0;
    let table = if inactive { dev.inactive_table() } else { dev.live_table() }.ok_or(Errno::Einval)?;
    let deps = table.devices();
    let mut payload = Vec::new();
    push_u32(&mut payload, u32::try_from(deps.len()).map_err(|_| Errno::Einval)?);
    push_u32(&mut payload, 0);
    for dep in deps { push_u64(&mut payload, dep.devt()); }
    fill_status(bytes, &dev);
    write_payload(bytes, &payload)
}

fn table_status(header: Header, bytes: &mut [u8]) -> DmResult<()> {
    let dev = device_of(header, bytes)?;
    let inactive = header.flags & uapi::DM_QUERY_INACTIVE_TABLE_FLAG != 0;
    let kind = if header.flags & uapi::DM_STATUS_TABLE_FLAG != 0 { StatusType::Table } else { StatusType::Info };
    let table = if inactive { dev.inactive_table() } else { dev.live_table() }.ok_or(Errno::Einval)?;
    let count = table.num_targets();
    let mut payload = Vec::new();
    for entry in table.targets() {
            let at = payload.len();
            payload.resize(at + TARGET_SPEC, 0);
            put_u64(&mut payload, at + TARGET_SECTOR, entry.begin)?;
            put_u64(&mut payload, at + TARGET_LENGTH, entry.len)?;
            write_fixed(&mut payload, at + TARGET_TYPE, uapi::DM_MAX_TYPE_NAME, entry.type_name)?;
            let body = entry.target.status(kind);
            payload.extend_from_slice(body.as_bytes());
            payload.push(0);
            let next = uapi::align8(payload.len() - at);
            payload.resize(at + next, 0);
            put_u32(&mut payload, at + TARGET_NEXT, u32::try_from(next).map_err(|_| Errno::Einval)?)?;
    }
    fill_status(bytes, &dev);
    write_payload(bytes, &payload)?;
    put_u32(bytes, TARGET_COUNT, u32::try_from(count).map_err(|_| Errno::Einval)?)
}

fn target_msg(header: Header, bytes: &mut [u8]) -> DmResult<()> {
    if header.data_start.checked_add(8).ok_or(Errno::Einval)? > header.data_size { return Err(Errno::Einval); }
    let sector = read_u64(bytes, header.data_start)?;
    let message = variable_cstr(bytes, header.data_start + 8, header.data_size)?;
    let args = crate::args::split_args(message);
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let dev = device_of(header, bytes)?;
    let table = if header.flags & uapi::DM_QUERY_INACTIVE_TABLE_FLAG != 0 { dev.inactive_table() } else { dev.live_table() }
        .ok_or(Errno::Einval)?;
    let target = table.find_target(sector).ok_or(Errno::Einval)?;
    let reply = target.target.message(&argv)?;
    fill_status(bytes, &dev);
    if let Some(reply) = reply {
        let mut payload = reply.into_bytes();
        payload.push(0);
        write_payload(bytes, &payload)?;
        let flags = read_u32(bytes, FLAGS)? | uapi::DM_DATA_OUT_FLAG;
        put_u32(bytes, FLAGS, flags)?;
    }
    Ok(())
}

fn set_geometry(header: Header, bytes: &mut [u8]) -> DmResult<()> {
    let data = variable_cstr(bytes, header.data_start, header.data_size)?;
    let fields: Vec<&str> = data.split_whitespace().collect();
    if fields.len() != 4 { return Err(Errno::Einval); }
    let cylinders = fields[0].parse::<u16>().map_err(|_| Errno::Einval)?;
    let heads = fields[1].parse::<u8>().map_err(|_| Errno::Einval)?;
    let sectors = fields[2].parse::<u8>().map_err(|_| Errno::Einval)?;
    let start = fields[3].parse::<u64>().map_err(|_| Errno::Einval)?;
    let dev = device_of(header, bytes)?;
    dev.set_geometry(Geometry { cylinders, heads, sectors, start })?;
    fill_status(bytes, &dev);
    clear_output(bytes)
}

fn list_devices(bytes: &mut [u8]) -> DmResult<()> {
    let mut payload = Vec::new();
    let mut last = None;
    for dev in registry::list() {
        let at = payload.len();
        if let Some(previous) = last { put_u32(&mut payload, previous + 8, u32::try_from(at - previous).map_err(|_| Errno::Einval)?)?; }
        payload.resize(at + 12, 0);
        put_u64(&mut payload, at, registry::devt_of(&dev))?;
        let name = dev.name();
        payload.extend_from_slice(name.as_bytes());
        payload.push(0);
        let tail = uapi::align8(payload.len() - at);
        payload.resize(at + tail, 0);
        last = Some(at);
    }
    write_payload(bytes, &payload)
}

fn list_versions(bytes: &mut [u8], only: Option<&str>) -> DmResult<()> {
    let mut payload = Vec::new();
    let mut last = None;
    for target in types::list().into_iter().filter(|t| only.is_none_or(|name| name == t.name)) {
        let at = payload.len();
        if let Some(previous) = last { put_u32(&mut payload, previous, u32::try_from(at - previous).map_err(|_| Errno::Einval)?)?; }
        payload.resize(at + 16, 0);
        put_u32(&mut payload, at + 4, target.version[0])?;
        put_u32(&mut payload, at + 8, target.version[1])?;
        put_u32(&mut payload, at + 12, target.version[2])?;
        payload.extend_from_slice(target.name.as_bytes());
        payload.push(0);
        let next = uapi::align8(payload.len() - at);
        payload.resize(at + next, 0);
        last = Some(at);
    }
    write_payload(bytes, &payload)
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
mod tests {
    use super::*;

    const CAPACITY: usize = 1024;
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn request() -> Vec<u8> {
        let mut bytes = alloc::vec![0; CAPACITY];
        put_u32(&mut bytes, DATA_SIZE, CAPACITY as u32).expect("size");
        put_u32(&mut bytes, DATA_START, DATA as u32).expect("start");
        bytes
    }

    fn named(name: &str) -> Vec<u8> {
        let mut bytes = request();
        write_fixed(&mut bytes, NAME, uapi::DM_NAME_LEN, name).expect("name");
        bytes
    }

    #[test]
    fn control_create_list_rename_and_remove_publish_one_real_mapper_node() {
        let _guard = TEST_LOCK.lock().expect("test lock");
        registry::reset_for_test();
        let original = "dm-control-fixture";
        let renamed = "dm-control-renamed";

        let mut create = named(original);
        dispatch(uapi::DM_DEV_CREATE, &mut create).expect("create");
        let dev = registry::by_name(original).expect("published mapper");
        assert_eq!(dev.minor, 0);
        assert!(block::registry::by_name("dm-0").is_some(), "block registry owns mapper disk");

        let mut listed = request();
        dispatch(uapi::DM_LIST_DEVICES, &mut listed).expect("list");
        assert!(listed[DATA..].windows(original.len()).any(|window| window == original.as_bytes()));

        let mut rename = named(original);
        rename[DATA..DATA + renamed.len()].copy_from_slice(renamed.as_bytes());
        rename[DATA + renamed.len()] = 0;
        dispatch(uapi::DM_DEV_RENAME, &mut rename).expect("rename");
        assert!(registry::by_name(original).is_none());
        assert_eq!(registry::by_name(renamed).expect("renamed mapper").minor, 0);

        let mut remove = named(renamed);
        dispatch(uapi::DM_DEV_REMOVE, &mut remove).expect("remove");
        assert!(registry::by_name(renamed).is_none());
        assert!(block::registry::by_name("dm-0").is_none());
    }

    #[test]
    fn version_stamps_reply_and_rejects_a_foreign_ioctl_type() {
        let mut bytes = request();
        dispatch(uapi::DM_VERSION, &mut bytes).expect("version");
        assert_eq!(read_u32(&bytes, VERSION).expect("major"), uapi::DM_VERSION_MAJOR);
        assert_eq!(dispatch(0, &mut bytes), Err(Errno::Enotty));
    }

    #[test]
    fn loaded_zero_table_resumes_and_services_the_published_block_node() {
        let _guard = TEST_LOCK.lock().expect("test lock");
        registry::reset_for_test();
        let name = "dm-zero-fixture";
        let mut create = named(name);
        dispatch(uapi::DM_DEV_CREATE, &mut create).expect("create");

        let mut load = named(name);
        let spec = 312usize;
        put_u32(&mut load, DATA_START, spec as u32).expect("table start");
        put_u32(&mut load, TARGET_COUNT, 1).expect("target count");
        put_u64(&mut load, spec + TARGET_SECTOR, 0).expect("sector");
        put_u64(&mut load, spec + TARGET_LENGTH, 8).expect("length");
        put_u32(&mut load, spec + TARGET_NEXT, 48).expect("next");
        write_fixed(&mut load, spec + TARGET_TYPE, uapi::DM_MAX_TYPE_NAME, "zero").expect("type");
        load[spec + TARGET_SPEC] = 0;
        dispatch(uapi::DM_TABLE_LOAD, &mut load).expect("load zero table");

        let mut resume = named(name);
        dispatch(uapi::DM_DEV_SUSPEND, &mut resume).expect("resume");
        assert_eq!(read_u32(&resume, EVENT_NR).expect("event number"), 1);
        let mut wait = named(name);
        put_u32(&mut wait, EVENT_NR, 0).expect("wait event number");
        dispatch(uapi::DM_DEV_WAIT, &mut wait).expect("wait for table event");
        assert_eq!(read_u32(&wait, EVENT_NR).expect("wait result"), 1);
        let disk = block::registry::by_name("dm-0").expect("published disk");
        let mut read = block::BlockRequest::new_read(0, 1, 512);
        disk.dev.submit_sync(&mut read).expect("zero read");
        assert_eq!(read.buffer, alloc::vec![0; 512]);

        let mut remove = named(name);
        dispatch(uapi::DM_DEV_REMOVE, &mut remove).expect("remove");
    }
}
