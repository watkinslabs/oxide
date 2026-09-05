//! Native NT file adapter over the existing VFS open and I/O descriptions.

#![cfg(target_os = "oxide-kernel")]

extern crate alloc;
use alloc::string::String;
use alloc::vec;
use syscall::errno::Errno;
use syscall::nt::{NtCall, NtCreateFileRequest, NtFileCall, NtFileIoRequest, NtOpenFileRequest, NtService};
use crate::nt_file_policy::CreateDisposition;

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xc000_0034;
const STATUS_OBJECT_NAME_COLLISION: u64 = 0xc000_0035;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const STATUS_SHARING_VIOLATION: u64 = 0xc000_0043;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;
const STATUS_NOT_FOUND: u64 = 0xc000_0225;
const STATUS_CANCELLED: u64 = 0xc000_0120;
const STATUS_TIMEOUT: u64 = 0x0000_0102;
const STATUS_END_OF_FILE: u64 = 0xc000_0011;
const FILE_READ_DATA: u32 = 0x0001;
const FILE_WRITE_DATA: u32 = 0x0002;
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
const FILE_LIST_DIRECTORY: u32 = 0x0001;
const FILE_APPEND_DATA: u32 = 0x0004;
const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
const FILE_GENERIC_READ: u32 = 0x0012_0089;
const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
const FILE_DIRECTORY_FILE: u32 = 0x1;
const MAX_NT_IO: usize = 16 * 1024 * 1024;
const FILE_BASIC_INFORMATION: u32 = 4;
const FILE_STANDARD_INFORMATION: u32 = 5;
const FILE_POSITION_INFORMATION: u32 = 14;
const FILE_END_OF_FILE_INFORMATION: u32 = 20;
const FILE_RENAME_INFORMATION: u32 = 10;
const FILE_DISPOSITION_INFORMATION: u32 = 13;
const DELETE_ACCESS: u32 = 0x0001_0000;
const FILE_INTERNAL_INFORMATION: u32 = 6;
const FILE_EA_INFORMATION: u32 = 7;
const FILE_ACCESS_INFORMATION: u32 = 8;
const FILE_MODE_INFORMATION: u32 = 16;
const FILE_NAME_INFORMATION: u32 = 9;
const FILE_ALIGNMENT_INFORMATION: u32 = 17;
const FILE_ALL_INFORMATION: u32 = 18;
const FILE_NETWORK_OPEN_INFORMATION: u32 = 34;
const FILE_ATTRIBUTE_TAG_INFORMATION: u32 = 35;
const FILE_PIPE_INFORMATION: u32 = 23;
const FILE_PIPE_LOCAL_INFORMATION: u32 = 24;
const NT_FILETIME_EPOCH_SECONDS: i64 = 11_644_473_600;
const STATUS_NO_MORE_FILES: u64 = 0x8000_0006;
const STATUS_BUFFER_TOO_SMALL: u64 = 0xc000_0023;
const STATUS_INVALID_INFO_CLASS: u64 = 0xc000_0003;
const STATUS_INFO_LENGTH_MISMATCH: u64 = 0xc000_0004;
const STATUS_INSTANCE_NOT_AVAILABLE: u64 = 0xc000_00ab;
const STATUS_PIPE_BUSY: u64 = 0xc000_00ae;
const STATUS_PIPE_DISCONNECTED: u64 = 0xc000_00b0;
const STATUS_PIPE_EMPTY: u64 = 0xc000_00d9;
const STATUS_NOT_SUPPORTED: u64 = 0xc000_00bb;
const FSCTL_PIPE_DISCONNECT: u32 = 0x0011_0004;
const FSCTL_PIPE_LISTEN: u32 = 0x0011_0008;
const FSCTL_PIPE_PEEK: u32 = 0x0011_000c;
const FSCTL_PIPE_TRANSCEIVE: u32 = 0x0011_0014;
const STATUS_PENDING: u64 = 0x0000_0103;
const EVENT_MODIFY_STATE: u32 = 0x0002;
const STATUS_PIPE_CONNECTED: u64 = 0xc000_00b2;
const REGISTRY_HIVE_MAX_BYTES: usize = 16 * 1024 * 1024;

fn put_io_status_information(io_status: u64, information: u64) -> Result<(), ()> {
    let address = io_status.checked_add(8).ok_or(())?;
    uaccess::put_user_u64(address, information).map_err(|_| ())
}

/// Dispatch the implemented synchronous NT file operations. # C: O(path) + O(bytes)
pub fn dispatch(call: NtFileCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    match call {
        NtFileCall::QueryAttributes { attributes, information } => query_attributes(cur, attributes.as_u64(), information.as_u64()),
        NtFileCall::QueryFullAttributes { attributes, information } => query_full_attributes(cur, attributes.as_u64(), information.as_u64()),
        NtFileCall::Create { request } => open_create(cur, request.as_u64()),
        NtFileCall::Open { request } => open_existing(cur, request.as_u64(), false),
        NtFileCall::Read { request } => io(cur, request.as_u64(), false),
        NtFileCall::Write { request } => io(cur, request.as_u64(), true),
        NtFileCall::QueryInformation { request } => query_information(cur, request.as_u64()),
        NtFileCall::QueryVolumeInformation { handle, io_status, information, length, information_class } =>
            crate::nt_file_volume::query(cur, handle, io_status.as_u64(), information.as_u64(), length, information_class),
        NtFileCall::SetInformation { request } => set_information(cur, request.as_u64()),
        NtFileCall::QueryDirectory { request } => query_directory(cur, request.as_u64()),
        NtFileCall::Lock { request } => crate::nt_file_lock::dispatch(cur, request.as_u64(), false),
        NtFileCall::Unlock { request } => crate::nt_file_lock::dispatch(cur, request.as_u64(), true),
        NtFileCall::Cancel { handle, io_status } => cancel(cur, handle, None, io_status.as_u64()),
        NtFileCall::CancelEx { handle, io, io_status } => cancel(cur, handle, io.map(|ptr| ptr.as_u64()), io_status.as_u64()),
        NtFileCall::CancelSynchronous { handle, io, io_status } => cancel_synchronous(cur, handle, io.map(|ptr| ptr.as_u64()), io_status.as_u64()),
        NtFileCall::Flush { handle, io_status } => flush(cur, handle, io_status.as_u64()),
    }
}

/// Dispatch the direct six-register Windows ABI used by native NTDLL exports.
/// Stack arguments are fetched only for the x86-64 Windows calling convention.
/// # C: O(path) + O(bytes)
pub fn dispatch_native(call: NtCall) -> Option<u64> {
    if let Some(result) = crate::nt_file_scatter::dispatch(call) { return Some(result); }
    if let Some(result) = crate::nt_file_gather::dispatch(call) { return Some(result); }
    match call.service {
        NtService::NtCreateNamedPipeFile => Some(native_create_named_pipe(call)),
        NtService::FsControlFile => Some(native_fs_control(call)),
        NtService::CreateFile => Some(native_create(call)),
        NtService::OpenFile => Some(native_open(call)),
        NtService::ReadFile => Some(native_io(call, false)),
        NtService::WriteFile => Some(native_io(call, true)),
        NtService::QueryInformationFile => Some(native_query_information(call)),
        NtService::NtQueryVolumeInformationFile => Some(crate::nt_file_volume::query(
            sched::live::current()?, call.args.a0 as u32, call.args.a1, call.args.a2,
            call.args.a3 as u32, call.args.a4 as u32,
        )),
        NtService::SetInformationFile => Some(native_set_information(call)),
        NtService::QueryDirectoryFile => Some(native_query_directory(call)),
        _ => None,
    }
}

/// Read one registry hive through the canonical VFS file owner. The registry
/// subsystem consumes the returned bounded envelope; it never opens or reads
/// a host path itself. # C: O(file bytes)
pub(crate) fn read_registry_hive(cur: &sched::Task, attributes: u64) -> Result<alloc::vec::Vec<u8>, u64> {
    if !cur.is_nt_personality() { return Err(STATUS_INVALID_PARAMETER); }
    let path = object_path(attributes).ok_or(STATUS_INVALID_PARAMETER)?;
    let lookup = crate::pathresolve::resolve_at_path(crate::pathresolve::AT_FDCWD, &path,
        crate::nt_path::windows_lookup_flags())
        .map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;
    if lookup.inode.file_type() != vfs::FileType::Regular { return Err(STATUS_INVALID_PARAMETER); }
    let stat = vfs::generic_fillattr(&lookup.inode, &vfs::IDENTITY);
    let length = usize::try_from(stat.size).map_err(|_| STATUS_INVALID_PARAMETER)?;
    if length == 0 || length > REGISTRY_HIVE_MAX_BYTES { return Err(STATUS_INVALID_PARAMETER); }
    let Some(cred) = crate::pathresolve::file_cred_for(cur) else { return Err(STATUS_ACCESS_DENIED); };
    let file = vfs::file::open_file_at(lookup.inode, lookup.dentry, vfs::OpenFlags::O_RDONLY,
        lookup.mnt_id, cred, None).map_err(|_| STATUS_ACCESS_DENIED)?;
    let mut bytes = alloc::vec![0; length];
    let mut at = 0;
    while at < bytes.len() {
        let count = file.read(&mut bytes[at..]).map_err(|_| STATUS_ACCESS_DENIED)?;
        if count == 0 { return Err(STATUS_END_OF_FILE); }
        at += count;
    }
    Ok(bytes)
}

fn native_fs_control(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || call.args.a0 > u32::MAX as u64 || call.args.a4 == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let Some(input) = crate::nt_dispatch::stack_argument(6) else { return STATUS_INVALID_PARAMETER; };
    let Some(input_length) = crate::nt_dispatch::stack_argument(7) else { return STATUS_INVALID_PARAMETER; };
    let Some(output) = crate::nt_dispatch::stack_argument(8) else { return STATUS_INVALID_PARAMETER; };
    let Some(output_length) = crate::nt_dispatch::stack_argument(9) else { return STATUS_INVALID_PARAMETER; };
    let handle = sched::nt_object::NtHandle::from_raw(call.args.a0 as u32);
    let table = cur.thread_group.nt_handles();
    let Some(object) = table.get(handle, 0) else { return STATUS_INVALID_HANDLE; };
    let Some(endpoint) = object.pipe_endpoint() else { return STATUS_INVALID_HANDLE; };
    let code = call.args.a5 as u32;
    if code == FSCTL_PIPE_PEEK {
        if input != 0 || input_length != 0 || output == 0 || output_length < 16 || output_length as usize > MAX_NT_IO { return STATUS_INVALID_PARAMETER; }
        let peek = endpoint.peek(output_length as usize - 16);
        let mut bytes = vec![0u8; 16usize.saturating_add(peek.data.len())];
        bytes[0..4].copy_from_slice(&(peek.state as u32).to_le_bytes());
        bytes[4..8].copy_from_slice(&(peek.available.min(u32::MAX as usize) as u32).to_le_bytes());
        bytes[8..12].copy_from_slice(&(peek.messages.min(u32::MAX as usize) as u32).to_le_bytes());
        bytes[12..16].copy_from_slice(&(peek.message_length.min(u32::MAX as usize) as u32).to_le_bytes());
        bytes[16..].copy_from_slice(&peek.data);
        if uaccess::copy_to_user(output, &bytes).is_err() { return STATUS_ACCESS_VIOLATION; }
        if uaccess::put_user_u64(call.args.a4, STATUS_SUCCESS).is_err()
            || put_io_status_information(call.args.a4, bytes.len() as u64).is_err() { return STATUS_ACCESS_VIOLATION; }
        return STATUS_SUCCESS;
    }
    if code == FSCTL_PIPE_TRANSCEIVE {
        if input == 0 || input_length == 0 || output == 0 || output_length == 0
            || input_length as usize > MAX_NT_IO || output_length as usize > MAX_NT_IO { return STATUS_INVALID_PARAMETER; }
        let Some(object) = table.get(handle, FILE_READ_DATA | FILE_WRITE_DATA) else { return STATUS_ACCESS_DENIED; };
        let Some(endpoint) = object.pipe_endpoint() else { return STATUS_INVALID_HANDLE; };
        let mut request = vec![0u8; input_length as usize];
        if uaccess::copy_from_user(&mut request, input).is_err() { return STATUS_ACCESS_VIOLATION; }
        if !matches!(endpoint.write(&request), sched::nt_object::NtPipeIo::Complete(_)) { return STATUS_PIPE_EMPTY; }
        let mut response = vec![0u8; output_length as usize];
        let sched::nt_object::NtPipeIo::Complete(bytes) = endpoint.read(&mut response) else { return STATUS_PIPE_EMPTY; };
        if uaccess::copy_to_user(output, &response[..bytes]).is_err() { return STATUS_ACCESS_VIOLATION; }
        if uaccess::put_user_u64(call.args.a4, STATUS_SUCCESS).is_err()
            || put_io_status_information(call.args.a4, bytes as u64).is_err() { return STATUS_ACCESS_VIOLATION; }
        return STATUS_SUCCESS;
    }
    if code != FSCTL_PIPE_DISCONNECT && code != FSCTL_PIPE_LISTEN {
        let _ = (input, input_length, output, output_length);
        return STATUS_NOT_SUPPORTED;
    }
    if input != 0 || input_length != 0 || output != 0 || output_length != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if call.args.a5 as u32 == FSCTL_PIPE_LISTEN {
        let status = match endpoint.listen() {
            sched::nt_object::NtPipeListen::Pending => STATUS_PENDING,
            sched::nt_object::NtPipeListen::Connected => STATUS_PIPE_CONNECTED,
        };
        if uaccess::put_user_u64(call.args.a4, status).is_err()
            || put_io_status_information(call.args.a4, 0).is_err() { return STATUS_ACCESS_VIOLATION; }
        return status;
    }
    if !endpoint.disconnect() { return STATUS_PIPE_DISCONNECTED; }
    if uaccess::put_user_u64(call.args.a4, STATUS_SUCCESS).is_err()
        || put_io_status_information(call.args.a4, 0).is_err() {
        return STATUS_ACCESS_VIOLATION;
    }
    STATUS_SUCCESS
}

fn native_create_named_pipe(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || call.args.a0 == 0 || call.args.a2 == 0
        || call.args.a1 > u32::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    let sharing = call.args.a4;
    let disposition = call.args.a5;
    let Some(options) = crate::nt_dispatch::stack_argument(6) else { return STATUS_INVALID_PARAMETER; };
    let Some(pipe_type) = crate::nt_dispatch::stack_argument(7) else { return STATUS_INVALID_PARAMETER; };
    let Some(read_mode) = crate::nt_dispatch::stack_argument(8) else { return STATUS_INVALID_PARAMETER; };
    let Some(completion_mode) = crate::nt_dispatch::stack_argument(9) else { return STATUS_INVALID_PARAMETER; };
    let Some(max_instances) = crate::nt_dispatch::stack_argument(10) else { return STATUS_INVALID_PARAMETER; };
    let Some(inbound_quota) = crate::nt_dispatch::stack_argument(11) else { return STATUS_INVALID_PARAMETER; };
    let Some(outbound_quota) = crate::nt_dispatch::stack_argument(12) else { return STATUS_INVALID_PARAMETER; };
    let Some(timeout_ptr) = crate::nt_dispatch::stack_argument(13) else { return STATUS_INVALID_PARAMETER; };
    if [sharing, disposition, options, pipe_type, read_mode, completion_mode,
        max_instances, inbound_quota, outbound_quota].iter().any(|value| *value > u32::MAX as u64) {
        return STATUS_INVALID_PARAMETER;
    }
    let timeout_100ns = if timeout_ptr == 0 { 0 } else {
        match uaccess::get_user_u64(timeout_ptr) { Ok(value) => value as i64, Err(_) => return STATUS_INVALID_PARAMETER }
    };
    let config = sched::nt_object::NtPipeConfig { pipe_type: pipe_type as u32,
        read_mode: read_mode as u32, completion_mode: completion_mode as u32,
        max_instances: max_instances as u32, inbound_quota: inbound_quota as u32,
        outbound_quota: outbound_quota as u32, timeout_100ns, sharing: sharing as u32 };
    if !sched::nt_object::NtPipe::validate_create(config, call.args.a1 as u32) {
        return STATUS_INVALID_PARAMETER;
    }
    let Some(path) = object_path(call.args.a2) else { return STATUS_INVALID_PARAMETER; };
    let table = cur.thread_group.nt_handles();
    let (pipe, state) = if let Some(existing) = sched::nt_object::lookup_object(&path, sched::nt_object::NtObjectType::NamedPipe) {
        let Some(pipe) = existing.pipe() else { return STATUS_INVALID_HANDLE; };
        if pipe.config().sharing != config.sharing || disposition as u32 == 2 {
            return STATUS_ACCESS_DENIED;
        }
        (pipe, sched::nt_object::NamedObjectState::Existing)
    } else {
        let object = table.new_named_pipe(config);
        let (published, state) = sched::nt_object::publish_named_pipe(&path, object);
        if state != sched::nt_object::NamedObjectState::Created { return STATUS_OBJECT_NAME_NOT_FOUND; }
        let Some(pipe) = published.pipe() else { return STATUS_INVALID_HANDLE; };
        (pipe, state)
    };
    if !pipe.reserve_instance() { return STATUS_INSTANCE_NOT_AVAILABLE; }
    let handle_object = table.new_named_pipe_endpoint(pipe, sched::nt_object::NtPipeSide::Server);
    let Some(handle) = table.insert(handle_object, call.args.a1 as u32 | SYNCHRONIZE_ACCESS) else { return STATUS_INVALID_PARAMETER; };
    if uaccess::put_user_u32(call.args.a0, handle.raw()).is_err() {
        let _ = table.close(handle);
        return STATUS_INVALID_PARAMETER;
    }
    if call.args.a3 != 0 {
        if uaccess::put_user_u64(call.args.a3, STATUS_SUCCESS).is_err()
            || uaccess::put_user_u64(call.args.a3 + 8, if state == sched::nt_object::NamedObjectState::Created { 2 } else { 1 }).is_err() {
            let _ = table.close(handle);
            return STATUS_INVALID_PARAMETER;
        }
    }
    STATUS_SUCCESS
}

fn native_create(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let Some(share) = crate::nt_dispatch::stack_argument(6) else { return STATUS_INVALID_PARAMETER; };
    let Some(disposition) = crate::nt_dispatch::stack_argument(7) else { return STATUS_INVALID_PARAMETER; };
    let Some(options) = crate::nt_dispatch::stack_argument(8) else { return STATUS_INVALID_PARAMETER; };
    if disposition > u32::MAX as u64 || share > u32::MAX as u64 || options > u32::MAX as u64
        || call.args.a5 > u32::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    let Some(disposition) = CreateDisposition::decode(disposition as u32) else { return STATUS_INVALID_PARAMETER; };
    if call.args.a0 == 0 || call.args.a2 == 0 || call.args.a1 > u32::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    let status = open_path(cur, call.args.a0, call.args.a1 as u32,
        call.args.a2, options as u32, share as u32, call.args.a5 as u32, disposition);
    if call.args.a3 != 0 { let _ = uaccess::put_user_u64(call.args.a3, status); let _ = uaccess::put_user_u64(call.args.a3 + 8, 0); }
    status
}

fn native_open(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let options = call.args.a5;
    if call.args.a0 == 0 || call.args.a2 == 0 || call.args.a1 > u32::MAX as u64 || call.args.a4 > u32::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    let status = open_path(cur, call.args.a0, call.args.a1 as u32,
        call.args.a2, options as u32, call.args.a4 as u32, 0, CreateDisposition::Open);
    if call.args.a3 != 0 { let _ = uaccess::put_user_u64(call.args.a3, status); let _ = uaccess::put_user_u64(call.args.a3 + 8, 0); }
    status
}

fn native_io(call: NtCall, write: bool) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let Some(length) = crate::nt_dispatch::stack_argument(6) else { return STATUS_INVALID_PARAMETER; };
    let Some(offset) = crate::nt_dispatch::stack_argument(7) else { return STATUS_INVALID_PARAMETER; };
    if call.args.a0 > u32::MAX as u64 || call.args.a4 == 0 || call.args.a5 == 0
        || length > u32::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    let offset = if offset == 0 { 0 } else { read_u64(offset).unwrap_or(u64::MAX) };
    if offset == u64::MAX { return STATUS_INVALID_PARAMETER; }
    native_io_values(cur, call.args.a0 as u32, call.args.a1, call.args.a4, call.args.a5,
        length as u32, offset, write)
}

fn native_io_values(cur: &sched::Task, handle: u32, event: u64, io_status: u64, buffer: u64,
                    length: u32, offset: u64, write: bool) -> u64 {
    if length as usize > MAX_NT_IO { return STATUS_INVALID_PARAMETER; }
    let required = if write { FILE_WRITE_DATA } else { FILE_READ_DATA };
    let native = sched::nt_object::NtHandle::from_raw(handle);
    let table = cur.thread_group.nt_handles();
    let Some(object) = table.get(native, required) else {
        return if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE };
    };
    let event_status = validate_io_event(cur, event);
    if event_status != STATUS_SUCCESS { return event_status; }
    if let Some(endpoint) = object.pipe_endpoint() {
        let mut data = vec![0u8; length as usize];
        let mut result = if write {
            if uaccess::copy_from_user(&mut data, buffer).is_err() { return STATUS_ACCESS_VIOLATION; }
            endpoint.write(&data)
        } else { endpoint.read(&mut data) };
        if matches!(result, sched::nt_object::NtPipeIo::WouldBlock) && endpoint.completion_mode() == 0 {
            let timeout = endpoint.pipe().config().timeout_100ns;
            let deadline = if timeout < 0 {
                timekeeper::monotonic_ns().saturating_add((-timeout as u64).saturating_mul(100))
            } else { 0 };
            // SAFETY: this native NT syscall is executing in process context;
            // the endpoint wait releases all transport locks before parking.
            endpoint.pipe().begin_io(cur.tid, io_status);
            let outcome = unsafe { endpoint.wait_for_io(write, deadline, cur.tid, io_status, timekeeper::monotonic_ns) };
            endpoint.pipe().end_io(cur.tid, io_status);
            if matches!(outcome, sched::nt_object::NtPipeWait::Cancelled) {
                write_io_status(io_status, STATUS_CANCELLED, 0);
                post_completion(&object, io_status, STATUS_CANCELLED, 0); signal_io_event(cur, event);
                return STATUS_CANCELLED;
            }
            if matches!(outcome, sched::nt_object::NtPipeWait::Ready) {
                result = if write { endpoint.write(&data) } else { endpoint.read(&mut data) };
            } else if matches!(outcome, sched::nt_object::NtPipeWait::TimedOut) {
                write_io_status(io_status, STATUS_TIMEOUT, 0);
                post_completion(&object, io_status, STATUS_TIMEOUT, 0); signal_io_event(cur, event);
                return STATUS_TIMEOUT;
            }
        }
        return match result {
            sched::nt_object::NtPipeIo::Complete(bytes) => {
                if !write && uaccess::copy_to_user(buffer, &data[..bytes]).is_err() { return STATUS_ACCESS_VIOLATION; }
                write_io_status(io_status, STATUS_SUCCESS, bytes as u64);
                post_completion(&object, io_status, STATUS_SUCCESS, bytes as u64); signal_io_event(cur, event);
                STATUS_SUCCESS
            }
            sched::nt_object::NtPipeIo::WouldBlock => {
                write_io_status(io_status, STATUS_PIPE_EMPTY, 0);
                post_completion(&object, io_status, STATUS_PIPE_EMPTY, 0); signal_io_event(cur, event);
                STATUS_PIPE_EMPTY
            }
            sched::nt_object::NtPipeIo::BrokenPipe => {
                write_io_status(io_status, STATUS_PIPE_DISCONNECTED, 0);
                post_completion(&object, io_status, STATUS_PIPE_DISCONNECTED, 0); signal_io_event(cur, event);
                STATUS_PIPE_DISCONNECTED
            }
        };
    }
    let Some(file) = object.file() else { return STATUS_INVALID_HANDLE; };
    let mut data = vec![0u8; length as usize];
    let result = if write {
        if uaccess::copy_from_user(&mut data, buffer).is_err() { return STATUS_ACCESS_VIOLATION; }
        if offset == 0 { file.write(&data).map(|n| n as u64) } else { file.pwrite(&data, offset as i64).map(|n| n as u64) }
    } else {
        let result = if offset == 0 { file.read(&mut data) } else { file.pread(&mut data, offset as i64) };
        if let Ok(n) = result { if uaccess::copy_to_user(buffer, &data[..n]).is_err() { return STATUS_ACCESS_VIOLATION; } }
        result.map(|n| n as u64)
    };
    let file_options = object.file_info().map_or(0, |info| info.options);
    match result {
        Ok(0) => {
            write_io_status(io_status, STATUS_END_OF_FILE, 0);
            post_completion(&object, io_status, STATUS_END_OF_FILE, 0); signal_io_event(cur, event);
            crate::nt_file_async_policy::regular_file_return_status(file_options,
                sched::nt_object::NtFileInfo::FD_TYPE_FILE, STATUS_END_OF_FILE, write)
        }
        Ok(bytes) => {
            write_io_status(io_status, STATUS_SUCCESS, bytes);
            post_completion(&object, io_status, STATUS_SUCCESS, bytes); signal_io_event(cur, event);
            crate::nt_file_async_policy::regular_file_return_status(file_options,
                sched::nt_object::NtFileInfo::FD_TYPE_FILE, STATUS_SUCCESS, write)
        }
        Err(error) => {
            let status = crate::nt_file_policy::status_from_errno(-(error as i64));
            write_io_status(io_status, status, 0); post_completion(&object, io_status, status, 0); signal_io_event(cur, event); status
        }
    }
}

fn native_query_information(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || call.args.a0 > u32::MAX as u64 || call.args.a1 == 0 || call.args.a2 == 0 || call.args.a3 > u32::MAX as u64 || call.args.a4 > u32::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    query_information_values(cur, call.args.a0 as u32, call.args.a1, call.args.a2, call.args.a3 as u32, call.args.a4 as u32)
}

fn native_set_information(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || call.args.a0 > u32::MAX as u64 || call.args.a1 == 0 || call.args.a2 == 0 || call.args.a3 > u32::MAX as u64 || call.args.a4 > u32::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    set_information_values(cur, call.args.a0 as u32, call.args.a1, call.args.a2, call.args.a3 as u32, call.args.a4 as u32)
}

fn native_query_directory(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    let Some(length) = crate::nt_dispatch::stack_argument(6) else { return STATUS_INVALID_PARAMETER; };
    let Some(class) = crate::nt_dispatch::stack_argument(7) else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || call.args.a0 > u32::MAX as u64 || call.args.a4 == 0 || call.args.a5 == 0 || length > u32::MAX as u64 || class > u32::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    query_directory_values(cur, call.args.a0 as u32, call.args.a4, call.args.a5, length as u32, class as u32)
}

fn query_attributes(cur: &sched::Task, attributes: u64, information: u64) -> u64 {
    if attributes == 0 || information == 0 { return STATUS_ACCESS_VIOLATION; }
    let table = cur.thread_group.nt_handles();
    let Some(path) = object_path_with_root(attributes, &table) else { return STATUS_INVALID_PARAMETER; };
    let lookup = crate::pathresolve::resolve_at_path(crate::pathresolve::AT_FDCWD, &path,
        crate::nt_path::windows_lookup_flags());
    let Ok(vp) = lookup else { return STATUS_OBJECT_NAME_NOT_FOUND; };
    let file_type = vp.inode.file_type();
    if file_type != vfs::FileType::Regular && file_type != vfs::FileType::Directory { return STATUS_INVALID_INFO_CLASS; }
    let stat = vfs::generic_fillattr(vp.inode.as_ref(), &vfs::IDENTITY);
    let mut out = [0u8; 40];
    put_i64(&mut out, 0, filetime(crate::nt_file_policy::creation_time(&stat)));
    put_i64(&mut out, 8, filetime(stat.atime));
    put_i64(&mut out, 16, filetime(stat.mtime));
    put_i64(&mut out, 24, filetime(stat.ctime));
    let file_attributes = vp.inode.windows_attributes().raw();
    out[32..36].copy_from_slice(&file_attributes.to_ne_bytes());
    if uaccess::copy_to_user(information, &out).is_err() { STATUS_ACCESS_VIOLATION } else { STATUS_SUCCESS }
}

fn query_full_attributes(cur: &sched::Task, attributes: u64, information: u64) -> u64 {
    if attributes == 0 || information == 0 { return STATUS_ACCESS_VIOLATION; }
    let table = cur.thread_group.nt_handles();
    let Some(path) = object_path_with_root(attributes, &table) else { return STATUS_INVALID_PARAMETER; };
    let lookup = crate::pathresolve::resolve_at_path(crate::pathresolve::AT_FDCWD, &path,
        crate::nt_path::windows_lookup_flags());
    let Ok(vp) = lookup else { return STATUS_OBJECT_NAME_NOT_FOUND; };
    let file_type = vp.inode.file_type();
    if file_type != vfs::FileType::Regular && file_type != vfs::FileType::Directory { return STATUS_INVALID_INFO_CLASS; }
    let stat = vfs::generic_fillattr(vp.inode.as_ref(), &vfs::IDENTITY);
    let mut out = [0u8; 56];
    put_i64(&mut out, 0, filetime(crate::nt_file_policy::creation_time(&stat)));
    put_i64(&mut out, 8, filetime(stat.atime));
    put_i64(&mut out, 16, filetime(stat.mtime));
    put_i64(&mut out, 24, filetime(stat.ctime));
    put_i64(&mut out, 32, stat.size as i64);
    put_i64(&mut out, 40, stat.size as i64);
    let file_attributes = vp.inode.windows_attributes().raw();
    out[48..52].copy_from_slice(&file_attributes.to_ne_bytes());
    if uaccess::copy_to_user(information, &out).is_err() { STATUS_ACCESS_VIOLATION } else { STATUS_SUCCESS }
}

fn flush(cur: &sched::Task, handle: u32, io_status: u64) -> u64 {
    if io_status == 0 { return STATUS_ACCESS_VIOLATION; }
    let table = cur.thread_group.nt_handles();
    let native = sched::nt_object::NtHandle::from_raw(handle);
    // Wine accepts either write or append access for NtFlushBuffersFile.
    let Some(object) = table.get(native, FILE_WRITE_DATA)
        .or_else(|| table.get(native, FILE_APPEND_DATA)) else {
        return if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE };
    };
    let Some(file) = object.file() else { return STATUS_INVALID_HANDLE; };
    let status = match file.vfs_fsync(false) {
        Ok(()) => STATUS_SUCCESS,
        Err(error) => crate::nt_file_policy::status_from_errno(-(error as i64)),
    };
    if uaccess::put_user_u64(io_status, status).is_err()
        || put_io_status_information(io_status, 0).is_err() {
        return STATUS_ACCESS_VIOLATION;
    }
    status
}

fn cancel(cur: &sched::Task, handle: u32, io: Option<u64>, io_status: u64) -> u64 {
    let table = cur.thread_group.nt_handles();
    let native = sched::nt_object::NtHandle::from_raw(handle);
    let Some(object) = table.get(native, 0) else { return STATUS_INVALID_HANDLE; };
    let pipe = object.pipe_endpoint();
    if object.file().is_none() && pipe.is_none() { return STATUS_INVALID_HANDLE; }
    let cancelled = pipe.as_ref().is_some_and(|endpoint| endpoint.pipe().cancel_io(cur.tid, io));
    let directory_watch = crate::nt_directory_notify::cancel(handle, cur.tid, io);
    let registry_watch = object.kind() == sched::nt_object::NtObjectType::Key
        && crate::nt_registry::cancel(object.id(), cur.tid, io);
    let status = if io.is_some() && !cancelled && !directory_watch && !registry_watch { STATUS_NOT_FOUND } else { STATUS_SUCCESS };
    if uaccess::put_user_u64(io_status, status).is_err() || put_io_status_information(io_status, 0).is_err() { return STATUS_ACCESS_VIOLATION; }
    status
}

fn cancel_synchronous(cur: &sched::Task, handle: u64, _io: Option<u64>, io_status: u64) -> u64 {
    if io_status == 0 { return STATUS_ACCESS_VIOLATION; }
    let table = cur.thread_group.nt_handles();
    let valid = if handle == u64::MAX - 1 {
        true
    } else if handle <= u32::MAX as u64 {
        let native = sched::nt_object::NtHandle::from_raw(handle as u32);
        table.get(native, 0).map(|object| object.kind() == sched::nt_object::NtObjectType::Thread).unwrap_or(false)
    } else { false };
    if !valid { return STATUS_INVALID_HANDLE; }
    if uaccess::put_user_u64(io_status, STATUS_NOT_FOUND).is_err() || put_io_status_information(io_status, 0).is_err() { return STATUS_ACCESS_VIOLATION; }
    STATUS_NOT_FOUND
}

fn read_u32(addr: u64) -> Result<u32, u64> { uaccess::get_user_u32(addr).map_err(|_| STATUS_INVALID_PARAMETER) }
fn read_u64(addr: u64) -> Result<u64, u64> { uaccess::get_user_u64(addr).map_err(|_| STATUS_INVALID_PARAMETER) }
fn read_u32_at(addr: u64, offset: u64) -> Result<u32, u64> { read_u32(addr.checked_add(offset).ok_or(STATUS_INVALID_PARAMETER)?) }
fn read_u64_at(addr: u64, offset: u64) -> Result<u64, u64> { read_u64(addr.checked_add(offset).ok_or(STATUS_INVALID_PARAMETER)?) }

fn open_create(cur: &sched::Task, addr: u64) -> u64 {
    let request = match (read_u64(addr), read_u32_at(addr, 8), read_u64_at(addr, 16),
        read_u64_at(addr, 24), read_u32_at(addr, 32), read_u32_at(addr, 36),
        read_u32_at(addr, 40), read_u32_at(addr, 44)) {
        (Ok(handle), Ok(desired_access), Ok(object_attributes), Ok(allocation_size),
         Ok(file_attributes), Ok(share_access), Ok(disposition), Ok(options)) =>
            NtCreateFileRequest { handle, desired_access, object_attributes, allocation_size,
                file_attributes, share_access, disposition, options },
        _ => return STATUS_INVALID_PARAMETER,
    };
    if request.handle == 0 || request.object_attributes == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(disposition) = CreateDisposition::decode(request.disposition) else { return STATUS_INVALID_PARAMETER; };
    open_path(cur, request.handle, request.desired_access, request.object_attributes,
        request.options, request.share_access, request.file_attributes, disposition)
}

fn open_existing(cur: &sched::Task, addr: u64, _create: bool) -> u64 {
    let request = match (read_u64(addr), read_u32_at(addr, 8), read_u64_at(addr, 16),
        read_u32_at(addr, 24), read_u32_at(addr, 28)) {
        (Ok(handle), Ok(desired_access), Ok(object_attributes), Ok(share_access), Ok(options)) =>
            NtOpenFileRequest { handle, desired_access, object_attributes, share_access, options },
        _ => return STATUS_INVALID_PARAMETER,
    };
    if request.handle == 0 || request.object_attributes == 0 { return STATUS_INVALID_PARAMETER; }
    open_path(cur, request.handle, request.desired_access, request.object_attributes, request.options,
        request.share_access, 0, CreateDisposition::Open)
}

fn open_path(cur: &sched::Task, output: u64, desired: u32, attrs: u64, options: u32,
             sharing: u32, file_attributes: u32, disposition: CreateDisposition) -> u64 {
    if sharing & !0x7 != 0 { return STATUS_INVALID_PARAMETER; }
    let delete = match crate::nt_file_policy::delete_on_close_admission(options, desired) {
        Some(delete) => delete,
        None => return STATUS_INVALID_PARAMETER,
    };
    let table = cur.thread_group.nt_handles();
    let Some(path) = object_path_with_root(attrs, &table) else { return STATUS_INVALID_PARAMETER; };
    if let Some(pipe) = sched::nt_object::lookup_object(&path, sched::nt_object::NtObjectType::NamedPipe) {
        return open_named_pipe(cur, output, desired, sharing, disposition, pipe);
    }
    let wants_write = desired & (GENERIC_WRITE | FILE_GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA) != 0;
    let wants_read = desired & (GENERIC_READ | FILE_GENERIC_READ | FILE_READ_DATA) != 0;
    if !wants_read && !wants_write && !crate::nt_file_policy::access_mask_admits_open(desired) {
        return STATUS_ACCESS_DENIED;
    }
    let mut flags = if wants_write {
        if desired & FILE_APPEND_DATA != 0 { vfs::OpenFlags::O_APPEND } else { vfs::OpenFlags::O_RDWR }
    } else { vfs::OpenFlags::O_RDONLY };
    if options & FILE_DIRECTORY_FILE != 0 { flags |= vfs::OpenFlags::O_DIRECTORY; }
    if options & FILE_NON_DIRECTORY_FILE != 0 && path.ends_with('/') { return STATUS_INVALID_PARAMETER; }
    let lookup = crate::pathresolve::resolve_at_path(crate::pathresolve::AT_FDCWD, &path,
        crate::nt_path::windows_lookup_flags());
    let (inode, dentry, mnt_id, created) = match lookup {
        Ok(_vp) if disposition.rejects_existing() => return STATUS_OBJECT_NAME_COLLISION,
        Ok(vp) => (vp.inode, vp.dentry, vp.mnt_id, false),
        Err(rv) if disposition.allows_missing() && rv == -(Errno::Enoent.as_i32() as i64) => {
            let mut parent_flags = crate::nt_path::windows_lookup_flags();
            parent_flags.parent = true;
            let Ok(parent) = crate::pathresolve::resolve_parent_at_flags(crate::pathresolve::AT_FDCWD, &path, parent_flags) else {
                return STATUS_OBJECT_NAME_NOT_FOUND;
            };
            let Some(name) = parent.last_component.clone() else { return STATUS_INVALID_PARAMETER; };
            let ctx = vfs::CreateCtx { idmap: &vfs::IDENTITY, cred: &crate::pathresolve::current_cred(), umask: cur.umask() as u16 };
            let mode = crate::nt_file_policy::creation_mode(file_attributes,
                options & FILE_DIRECTORY_FILE != 0);
            match vfs::vfs_create_at(&parent, &name, mode, &ctx) {
                Ok((inode, dentry)) => (inode, dentry, parent.mnt_id, true),
                Err(error) => return crate::nt_file_policy::status_from_errno(-(error as i64)),
            }
        }
        Err(rv) => return crate::nt_file_policy::status_from_errno(rv),
    };
    if let Some(rv) = crate::open_common::enforce_open_perm(&inode, mnt_id, flags.bits(), created) {
        return crate::nt_file_policy::status_from_errno(rv);
    }
    let Some(cred) = crate::pathresolve::file_cred_for(cur) else { return STATUS_ACCESS_DENIED; };
    let Ok(file) = vfs::file::open_file_at(inode, dentry, flags, mnt_id, cred, None) else {
        return STATUS_ACCESS_DENIED;
    };
    let rollback = if created {
        sched::nt_object::NtDeleteOnClose::new(file.as_ref(), true)
    } else { None };
    let delete_state = if delete {
        if sched::nt_object::NtDeleteOnClose::new(file.as_ref(), false).is_none() { return STATUS_INVALID_PARAMETER; }
        true
    } else { false };
    let Some(share) = sched::nt_object::NtFileShare::claim(&file, desired, sharing) else {
        return STATUS_SHARING_VIOLATION;
    };
    if !created && disposition.truncates_existing() && file.inode().truncate(0).is_err() {
        return STATUS_ACCESS_DENIED;
    }
    let info = sched::nt_object::NtFileInfo::from_file(file.as_ref(), options);
    let object = table.new_file_with_share_and_delete_and_info(file, share, delete_state, info);
    let Some(handle) = table.insert(object, desired | SYNCHRONIZE_ACCESS) else {
        return STATUS_INVALID_PARAMETER;
    };
    if uaccess::put_user_u32(output, handle.raw()).is_err() {
        let _ = table.close(handle);
        return STATUS_INVALID_PARAMETER;
    }
    if let Some(rollback) = rollback { rollback.set_armed(false); }
    STATUS_SUCCESS
}

fn open_named_pipe(cur: &sched::Task, output: u64, desired: u32, sharing: u32,
                   disposition: CreateDisposition, object: alloc::sync::Arc<sched::nt_object::NtObject>) -> u64 {
    if disposition.rejects_existing() || sharing & !0x7 != 0 { return STATUS_INVALID_PARAMETER; }
    let Some(pipe) = object.pipe() else { return STATUS_INVALID_HANDLE; };
    if sharing & !pipe.config().sharing != 0 { return STATUS_SHARING_VIOLATION; }
    if !pipe.connect() { return STATUS_PIPE_BUSY; }
    let table = cur.thread_group.nt_handles();
    let client = table.new_named_pipe_endpoint(pipe, sched::nt_object::NtPipeSide::Client);
    let Some(handle) = table.insert(client, desired | SYNCHRONIZE_ACCESS) else { return STATUS_INVALID_PARAMETER; };
    if uaccess::put_user_u32(output, handle.raw()).is_err() { let _ = table.close(handle); return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn io(cur: &sched::Task, addr: u64, write: bool) -> u64 {
    let request = match (read_u32(addr), read_u32_at(addr, 4), read_u64_at(addr, 8),
        read_u64_at(addr, 16), read_u32_at(addr, 24), read_u64_at(addr, 32)) {
        (Ok(handle), Ok(event), Ok(io_status), Ok(buffer), Ok(length), Ok(offset)) =>
            NtFileIoRequest { handle, event, io_status, buffer, length, offset },
        _ => return STATUS_INVALID_PARAMETER,
    };
    if request.io_status == 0 || request.buffer == 0 || request.length as usize > MAX_NT_IO {
        return STATUS_INVALID_PARAMETER;
    }
    let required = if write { FILE_WRITE_DATA } else { FILE_READ_DATA };
    let native = sched::nt_object::NtHandle::from_raw(request.handle);
    let table = cur.thread_group.nt_handles();
    let Some(object) = table.get(native, required) else {
        return if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE };
    };
    let event_status = validate_io_event(cur, request.event as u64);
    if event_status != STATUS_SUCCESS { return event_status; }
    let Some(file) = object.file() else { return STATUS_INVALID_HANDLE; };
    let mut data = vec![0u8; request.length as usize];
    let result = if write {
        if uaccess::copy_from_user(&mut data, request.buffer).is_err() { return STATUS_INVALID_PARAMETER; }
        file.write(&data).map(|n| n as u64)
    } else {
        let result = if request.offset == 0 { file.read(&mut data) } else {
            let Ok(offset) = read_u64(request.offset) else { return STATUS_INVALID_PARAMETER; };
            file.pread(&mut data, offset as i64)
        };
        if let Ok(n) = result { if uaccess::copy_to_user(request.buffer, &data[..n]).is_err() { return STATUS_INVALID_PARAMETER; } }
        result.map(|n| n as u64)
    };
    match result {
        Ok(0) => {
            write_io_status(request.io_status, STATUS_END_OF_FILE, 0);
            post_completion(&object, request.io_status, STATUS_END_OF_FILE, 0); signal_io_event(cur, request.event as u64);
            STATUS_END_OF_FILE
        }
        Ok(bytes) => {
            write_io_status(request.io_status, STATUS_SUCCESS, bytes);
            post_completion(&object, request.io_status, STATUS_SUCCESS, bytes); signal_io_event(cur, request.event as u64);
            STATUS_SUCCESS
        }
        Err(error) => {
            let status = crate::nt_file_policy::status_from_errno(-(error as i64));
            write_io_status(request.io_status, status, 0);
            post_completion(&object, request.io_status, status, 0); signal_io_event(cur, request.event as u64);
            status
        }
    }
}

pub(crate) fn write_io_status(addr: u64, status: u64, information: u64) {
    let Some(information_addr) = addr.checked_add(8) else { return; };
    let _ = uaccess::put_user_u64(addr, status);
    let _ = uaccess::put_user_u64(information_addr, information);
}

pub(crate) fn post_completion(object: &sched::nt_object::NtObject, overlapped: u64, status: u64, information: u64) {
    let Some((port, key)) = object.file_completion() else { return; };
    port.post(sched::nt_object::NtCompletionPacket { key, overlapped, status: status as u32, information });
}

fn validate_io_event(cur: &sched::Task, event: u64) -> u64 {
    if event == 0 { return STATUS_SUCCESS; }
    if event > u32::MAX as u64 { return crate::nt_file_async_policy::io_event_status(event, false, false, false); }
    let handle = sched::nt_object::NtHandle::from_raw(event as u32);
    let table = cur.thread_group.nt_handles();
    let exists = table.contains(handle);
    let is_event = table.get(handle, 0).and_then(|object| object.event()).is_some();
    let can_modify = table.get(handle, EVENT_MODIFY_STATE).and_then(|object| object.event()).is_some();
    crate::nt_file_async_policy::io_event_status(event, exists, is_event, can_modify)
}

fn signal_io_event(cur: &sched::Task, event: u64) {
    if event == 0 || event > u32::MAX as u64 { return; }
    let handle = sched::nt_object::NtHandle::from_raw(event as u32);
    let table = cur.thread_group.nt_handles();
    if let Some(object) = table.get(handle, EVENT_MODIFY_STATE) {
        if let Some(event) = object.event() { event.set(); table.wake_waiters(); }
    }
}

fn query_information(cur: &sched::Task, addr: u64) -> u64 {
    let Some(io_address) = addr.checked_add(8) else { return STATUS_INVALID_PARAMETER; };
    let Some(information_address) = addr.checked_add(16) else { return STATUS_INVALID_PARAMETER; };
    let Some(length_address) = addr.checked_add(24) else { return STATUS_INVALID_PARAMETER; };
    let Some(class_address) = addr.checked_add(28) else { return STATUS_INVALID_PARAMETER; };
    let (handle, io_status, information, length, class) = match (
        read_u32(addr), read_u64(io_address), read_u64(information_address),
        read_u32(length_address), read_u32(class_address)) {
        (Ok(handle), Ok(io_status), Ok(information), Ok(length), Ok(class)) =>
            (handle, io_status, information, length, class),
        _ => return STATUS_INVALID_PARAMETER,
    };
    query_information_values(cur, handle, io_status, information, length, class)
}

fn query_information_values(cur: &sched::Task, handle: u32, io_status: u64, information: u64, length: u32, class: u32) -> u64 {
    if io_status == 0 || information == 0 { return STATUS_INVALID_PARAMETER; }
    let native = sched::nt_object::NtHandle::from_raw(handle);
    let table = cur.thread_group.nt_handles();
    let Some(object) = table.get(native, FILE_READ_ATTRIBUTES) else {
        return if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE };
    };
    if class == FILE_PIPE_INFORMATION || class == FILE_PIPE_LOCAL_INFORMATION {
        let Some(endpoint) = object.pipe_endpoint() else { return STATUS_INVALID_HANDLE; };
        let (pipe_info, local_info) = endpoint.information();
        let needed = if class == FILE_PIPE_INFORMATION { 8 } else { 40 };
        if (length as usize) < needed { write_io_status(io_status, STATUS_INFO_LENGTH_MISMATCH, 0); return STATUS_INFO_LENGTH_MISMATCH; }
        let mut out = vec![0u8; needed];
        if class == FILE_PIPE_INFORMATION {
            out[0..4].copy_from_slice(&pipe_info[0].to_le_bytes());
            out[4..8].copy_from_slice(&pipe_info[1].to_le_bytes());
        } else {
            for (index, value) in local_info.iter().enumerate() { out[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes()); }
        }
        if uaccess::copy_to_user(information, &out).is_err() { write_io_status(io_status, STATUS_ACCESS_VIOLATION, 0); return STATUS_ACCESS_VIOLATION; }
        write_io_status(io_status, STATUS_SUCCESS, needed as u64);
        return STATUS_SUCCESS;
    }
    let Some(file) = object.file() else { return STATUS_INVALID_HANDLE; };
    if class == FILE_MODE_INFORMATION {
        if length < core::mem::size_of::<u32>() as u32 {
            write_io_status(io_status, STATUS_INFO_LENGTH_MISMATCH, 0);
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        let mode = object.file_info().map_or(0, |info| crate::nt_file_policy::file_mode_from_options(info.options));
        if uaccess::put_user_u32(information, mode).is_err() {
            write_io_status(io_status, STATUS_ACCESS_VIOLATION, 0);
            return STATUS_ACCESS_VIOLATION;
        }
        write_io_status(io_status, STATUS_SUCCESS, core::mem::size_of::<u32>() as u64);
        return STATUS_SUCCESS;
    }
    let stat = vfs::generic_fillattr(file.inode(), &vfs::IDENTITY);
    let is_directory = file.inode().file_type() == vfs::FileType::Directory;
    let file_attributes = file.inode().windows_attributes().raw();
    let path = String::from_utf8(file.dentry().absolute_path()).ok()
        .and_then(|path| crate::nt_path::render_windows_path(&path));
    let name: alloc::vec::Vec<u16> = path.as_deref().unwrap_or("").encode_utf16().collect();
    let Some(name_bytes) = name.len().checked_mul(2) else { return STATUS_INVALID_PARAMETER; };
    let Some(all_size) = 100usize.checked_add(name_bytes) else { return STATUS_INVALID_PARAMETER; };
    let mut out = alloc::vec::Vec::new();
    let needed = match class {
        FILE_BASIC_INFORMATION => {
            out.resize(40, 0);
            put_i64(&mut out, 0, filetime(crate::nt_file_policy::creation_time(&stat)));
            put_i64(&mut out, 8, filetime(stat.atime));
            put_i64(&mut out, 16, filetime(stat.mtime));
            put_i64(&mut out, 24, filetime(stat.ctime));
            out[32..36].copy_from_slice(&file_attributes.to_ne_bytes());
            40
        }
        FILE_STANDARD_INFORMATION => {
            out.resize(24, 0);
            put_i64(&mut out, 0, stat.size as i64);
            put_i64(&mut out, 8, stat.size as i64);
            out[16..20].copy_from_slice(&stat.nlink.to_ne_bytes());
            out[21] = is_directory as u8;
            24
        }
        FILE_INTERNAL_INFORMATION => { out.resize(8, 0); put_i64(&mut out, 0, stat.ino as i64); 8 }
        FILE_EA_INFORMATION => { out.resize(4, 0); 4 }
        FILE_ACCESS_INFORMATION => {
            out.resize(4, 0);
            let access = table.access(native).unwrap_or(0);
            out[0..4].copy_from_slice(&access.to_ne_bytes());
            4
        }
        FILE_NAME_INFORMATION => {
            out.resize(4 + name_bytes, 0);
            out[0..4].copy_from_slice(&(name_bytes as u32).to_ne_bytes());
            for (index, unit) in name.iter().enumerate() { out[4 + index * 2..6 + index * 2].copy_from_slice(&unit.to_ne_bytes()); }
            4 + name_bytes
        }
        FILE_POSITION_INFORMATION => { out.resize(8, 0); put_i64(&mut out, 0, file.pos() as i64); 8 }
        FILE_ALIGNMENT_INFORMATION => { out.resize(4, 0); out[0..4].copy_from_slice(&1u32.to_ne_bytes()); 4 }
        FILE_END_OF_FILE_INFORMATION => { out.resize(8, 0); put_i64(&mut out, 0, stat.size as i64); 8 }
        FILE_ALL_INFORMATION => {
            out.resize(all_size, 0);
            put_i64(&mut out, 0, filetime(crate::nt_file_policy::creation_time(&stat)));
            put_i64(&mut out, 8, filetime(stat.atime));
            put_i64(&mut out, 16, filetime(stat.mtime));
            put_i64(&mut out, 24, filetime(stat.ctime));
            put_i64(&mut out, 40, stat.size as i64);
            put_i64(&mut out, 48, stat.size as i64);
            out[56..60].copy_from_slice(&stat.nlink.to_ne_bytes());
            out[61] = is_directory as u8;
            out[92..96].copy_from_slice(&1u32.to_ne_bytes());
            out[96..100].copy_from_slice(&(name_bytes as u32).to_ne_bytes());
            for (index, unit) in name.iter().enumerate() { out[100 + index * 2..102 + index * 2].copy_from_slice(&unit.to_ne_bytes()); }
            all_size
        }
        FILE_NETWORK_OPEN_INFORMATION => {
            out.resize(56, 0);
            put_i64(&mut out, 0, filetime(crate::nt_file_policy::creation_time(&stat)));
            put_i64(&mut out, 8, filetime(stat.atime));
            put_i64(&mut out, 16, filetime(stat.mtime));
            put_i64(&mut out, 24, filetime(stat.ctime));
            put_i64(&mut out, 32, stat.size as i64);
            put_i64(&mut out, 40, stat.size as i64);
            out[48..52].copy_from_slice(&file_attributes.to_ne_bytes());
            56
        }
        FILE_ATTRIBUTE_TAG_INFORMATION => { out.resize(8, 0); out[0..4].copy_from_slice(&file_attributes.to_ne_bytes()); 8 }
        _ => return STATUS_INVALID_PARAMETER,
    };
    if (length as usize) < needed {
        write_io_status(io_status, STATUS_INFO_LENGTH_MISMATCH, 0);
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    if uaccess::copy_to_user(information, &out[..needed]).is_err() {
        write_io_status(io_status, STATUS_ACCESS_VIOLATION, 0);
        return STATUS_ACCESS_VIOLATION;
    }
    write_io_status(io_status, STATUS_SUCCESS, needed as u64);
    STATUS_SUCCESS
}

fn set_information(cur: &sched::Task, addr: u64) -> u64 {
    let Some(io_address) = addr.checked_add(8) else { return STATUS_INVALID_PARAMETER; };
    let Some(information_address) = addr.checked_add(16) else { return STATUS_INVALID_PARAMETER; };
    let Some(length_address) = addr.checked_add(24) else { return STATUS_INVALID_PARAMETER; };
    let Some(class_address) = addr.checked_add(28) else { return STATUS_INVALID_PARAMETER; };
    let (handle, io_status, information, length, class) = match (
        read_u32(addr), read_u64(io_address), read_u64(information_address),
        read_u32(length_address), read_u32(class_address)) {
        (Ok(handle), Ok(io_status), Ok(information), Ok(length), Ok(class)) =>
            (handle, io_status, information, length, class),
        _ => return STATUS_INVALID_PARAMETER,
    };
    set_information_values(cur, handle, io_status, information, length, class)
}

fn set_information_values(cur: &sched::Task, handle: u32, io_status: u64, information: u64, length: u32, class: u32) -> u64 {
    if io_status == 0 || information == 0 { return STATUS_INVALID_PARAMETER; }
    if class == FILE_DISPOSITION_INFORMATION {
        if !crate::nt_file_policy::disposition_information_valid(length) { return STATUS_INVALID_PARAMETER; }
    } else if length < 8 { return STATUS_INVALID_PARAMETER; }
    let native = sched::nt_object::NtHandle::from_raw(handle);
    let table = cur.thread_group.nt_handles();
    let required = match class {
        FILE_BASIC_INFORMATION => FILE_WRITE_ATTRIBUTES,
        FILE_DISPOSITION_INFORMATION => DELETE_ACCESS,
        _ => FILE_WRITE_DATA,
    };
    let Some(object) = table.get(native, required) else {
        return if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE };
    };
    if class == FILE_PIPE_INFORMATION {
        if length < 8 { return STATUS_INVALID_PARAMETER; }
        let Some(endpoint) = object.pipe_endpoint() else { return STATUS_INVALID_HANDLE; };
        let Ok(read_mode) = read_u32(information) else { return STATUS_INVALID_PARAMETER; };
        let Ok(completion_mode) = read_u32_at(information, 4) else { return STATUS_INVALID_PARAMETER; };
        if !endpoint.set_modes(read_mode, completion_mode) { return STATUS_INVALID_PARAMETER; }
        write_io_status(io_status, STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    }
    let Some(file) = object.file() else { return STATUS_INVALID_HANDLE; };
    if class == FILE_BASIC_INFORMATION {
        if length < 40 { return STATUS_INVALID_PARAMETER; }
        let Ok(creation) = read_u64(information) else { return STATUS_INVALID_PARAMETER; };
        let Ok(atime) = read_u64_at(information, 8) else { return STATUS_INVALID_PARAMETER; };
        let Ok(mtime) = read_u64_at(information, 16) else { return STATUS_INVALID_PARAMETER; };
        let Ok(change) = read_u64_at(information, 24) else { return STATUS_INVALID_PARAMETER; };
        let Ok(attributes) = read_u32_at(information, 32) else { return STATUS_INVALID_PARAMETER; };
        if crate::nt_file_policy::file_basic_unsupported_fields(creation as i64, change as i64) {
            return STATUS_NOT_SUPPORTED;
        }
        let is_directory = file.inode().file_type() == vfs::FileType::Directory;
        let Some(windows_attributes) = vfs::WindowsFileAttributes::from_raw(attributes, is_directory)
            .or_else(|| (attributes == 0).then(|| vfs::WindowsFileAttributes::initial(is_directory, false))) else {
            return STATUS_INVALID_PARAMETER;
        };
        if attributes != 0 { file.inode().set_windows_attributes(windows_attributes); }
        let mut ia = vfs::Iattr { ctime: vfs::Timespec64::ZERO, ..Default::default() };
        if let Some(value) = crate::nt_file_policy::filetime_to_timespec(atime as i64) {
            ia.valid |= vfs::ATTR_ATIME | vfs::ATTR_ATIME_SET; ia.atime = value;
        }
        if let Some(value) = crate::nt_file_policy::filetime_to_timespec(mtime as i64) {
            ia.valid |= vfs::ATTR_MTIME | vfs::ATTR_MTIME_SET; ia.mtime = value;
        }
        if ia.valid != 0 {
            let cred = crate::pathresolve::current_cred();
            if vfs::notify_change_mnt(file.inode(), file.mnt_id(), &mut ia, &cred,
                                      vfs::inode_times::realtime_now_ns()).is_err() {
                return STATUS_ACCESS_DENIED;
            }
        }
        write_io_status(io_status, STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    }
    if class == FILE_RENAME_INFORMATION { return set_rename_information(file.as_ref(), information, length, io_status); }
    if class == FILE_DISPOSITION_INFORMATION {
        let mut value = [0u8; 1];
        if uaccess::copy_from_user(&mut value, information).is_err() { return STATUS_INVALID_PARAMETER; }
        let Some(state) = object.delete_on_close() else { return STATUS_INVALID_PARAMETER; };
        state.set_armed(crate::nt_file_policy::disposition_requests_delete(value[0]));
        write_io_status(io_status, STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    }
    let Ok(value) = read_u64(information) else { return STATUS_INVALID_PARAMETER; };
    let result = match class {
        FILE_POSITION_INFORMATION => { file.set_pos(value); Ok(()) }
        FILE_END_OF_FILE_INFORMATION => file.inode().truncate(value).map_err(|_| ()),
        _ => return STATUS_INVALID_PARAMETER,
    };
    match result {
        Ok(()) => { write_io_status(io_status, STATUS_SUCCESS, 0); STATUS_SUCCESS }
        Err(()) => { write_io_status(io_status, STATUS_ACCESS_DENIED, 0); STATUS_ACCESS_DENIED }
    }
}

fn set_rename_information(file: &vfs::File, information: u64, length: u32, io_status: u64) -> u64 {
    const RENAME_HEADER_BYTES: usize = 20;
    let length = length as usize;
    if length < RENAME_HEADER_BYTES { return STATUS_INVALID_PARAMETER; }
    let Ok(replace) = read_u32(information) else { return STATUS_INVALID_PARAMETER; };
    let Ok(root) = read_u64_at(information, 8) else { return STATUS_INVALID_PARAMETER; };
    let Ok(name_len) = read_u32_at(information, 16) else { return STATUS_INVALID_PARAMETER; };
    let name_len = name_len as usize;
    if replace > 1 || root != 0 || name_len == 0 || name_len & 1 != 0
        || name_len > length - RENAME_HEADER_BYTES || name_len > 32766 { return STATUS_INVALID_PARAMETER; }
    let mut bytes = vec![0u8; name_len];
    let Some(name_address) = information.checked_add(RENAME_HEADER_BYTES as u64) else { return STATUS_INVALID_PARAMETER; };
    if uaccess::copy_from_user(&mut bytes, name_address).is_err() { return STATUS_INVALID_PARAMETER; }
    let Some(raw_target) = utf16_string(&bytes) else { return STATUS_INVALID_PARAMETER; };
    let Some(target) = crate::nt_path::normalize_path(&raw_target) else { return STATUS_INVALID_PARAMETER; };
    let source = vfs::path_from_bytes(&file.dentry().absolute_path());
    let flags = if replace == 0 { vfs::namei::RENAME_NOREPLACE } else { 0 };
    let status = crate::s082_rename::rename_kernel_paths(&source, &target, flags);
    if status == 0 {
        write_io_status(io_status, STATUS_SUCCESS, 0);
        STATUS_SUCCESS
    } else { crate::nt_file_policy::status_from_errno(status) }
}

fn query_directory(cur: &sched::Task, addr: u64) -> u64 {
    let (handle, io_status, information, length, class) = match (
        read_u32(addr), read_u64_at(addr, 8), read_u64_at(addr, 16),
        read_u32_at(addr, 24), read_u32_at(addr, 28)) {
        (Ok(handle), Ok(io_status), Ok(information), Ok(length), Ok(class)) =>
            (handle, io_status, information, length, class),
        _ => return STATUS_INVALID_PARAMETER,
    };
    query_directory_values(cur, handle, io_status, information, length, class)
}

fn query_directory_values(cur: &sched::Task, handle: u32, io_status: u64, information: u64, length: u32, class: u32) -> u64 {
    if io_status == 0 || information == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let Some(layout) = crate::nt_file_policy::directory_info_layout(class) else { return STATUS_INVALID_INFO_CLASS; };
    // FILE_NAMES_INFORMATION has a fixed 12-byte header.  NT validates the
    // caller's buffer contract before touching the directory cursor; doing
    // this here also prevents a zero-sized emitter from being mistaken for an
    // exhausted directory.
    if length < layout.header as u32 {
        write_io_status(io_status, STATUS_INFO_LENGTH_MISMATCH, 0);
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    let native = sched::nt_object::NtHandle::from_raw(handle);
    let table = cur.thread_group.nt_handles();
    let Some(object) = table.get(native, FILE_LIST_DIRECTORY) else {
        return if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE };
    };
    let Some(file) = object.file() else { return STATUS_INVALID_HANDLE; };
    if file.inode().file_type() != vfs::FileType::Directory { return STATUS_INVALID_PARAMETER; }
    let parent_ino = file.dentry().parent().and_then(|d| d.inode()).map(|i| i.ino())
        .unwrap_or_else(|| file.inode().ino());
    let mut emitter = NameEmitter::new(length as usize, layout);
    let (result, next_pos) = vfs::readdir_dots(file.as_ref(), file.inode().ino(), parent_ino,
        file.pos(), &mut emitter);
    if result.is_err() { return STATUS_INVALID_PARAMETER; }
    if emitter.bytes.is_empty() {
        // A directory with entries and a buffer too small for the first
        // record is not exhausted.  Wine preserves the NT distinction here:
        // callers grow the buffer on STATUS_BUFFER_TOO_SMALL, while
        // STATUS_NO_MORE_FILES terminates enumeration.
        if emitter.attempted {
            write_io_status(io_status, STATUS_BUFFER_TOO_SMALL, 0);
            return STATUS_BUFFER_TOO_SMALL;
        }
        write_io_status(io_status, STATUS_NO_MORE_FILES, 0);
        return STATUS_NO_MORE_FILES;
    }
    file.set_pos(next_pos);
    if uaccess::copy_to_user(information, &emitter.bytes).is_err() {
        return STATUS_INVALID_PARAMETER;
    }
    write_io_status(io_status, STATUS_SUCCESS, emitter.bytes.len() as u64);
    STATUS_SUCCESS
}

struct NameEmitter {
    bytes: alloc::vec::Vec<u8>,
    capacity: usize,
    last: Option<usize>,
    attempted: bool,
    layout: crate::nt_file_policy::DirectoryInfoLayout,
}

impl NameEmitter {
    fn new(capacity: usize, layout: crate::nt_file_policy::DirectoryInfoLayout) -> Self {
        Self { bytes: alloc::vec::Vec::new(), capacity, last: None, attempted: false, layout }
    }
}

impl vfs::DirEmit for NameEmitter {
    fn emit(&mut self, name: &str, ino: u64, kind: vfs::FileType, _next_pos: u64) -> bool {
        self.attempted = true;
        let utf16: alloc::vec::Vec<u16> = name.encode_utf16().collect();
        let Some(name_bytes) = utf16.len().checked_mul(2) else { return false; };
        let Some(record_len) = self.layout.header.checked_add(name_bytes) else {
            return false;
        };
        let Some(aligned) = record_len.checked_add(7).map(|value| value & !7) else { return false; };
        let Some(remaining) = self.capacity.checked_sub(self.bytes.len()) else { return false; };
        if aligned > remaining { return false; }
        let offset = self.bytes.len();
        if let Some(last) = self.last {
            let delta = (offset - last) as u32;
            self.bytes[last..last + 4].copy_from_slice(&delta.to_ne_bytes());
        }
        let Some(end) = offset.checked_add(aligned) else { return false; };
        self.bytes.resize(end, 0);
        self.bytes[offset + 4..offset + 8].copy_from_slice(&0u32.to_ne_bytes());
        let name_length_end = self.layout.name_length + 4;
        self.bytes[offset + self.layout.name_length..offset + name_length_end].copy_from_slice(&(name_bytes as u32).to_ne_bytes());
        if let Some(field) = self.layout.attributes {
            let value = if kind == vfs::FileType::Directory { 0x10u32 } else { 0x80u32 };
            self.bytes[offset + field..offset + field + 4].copy_from_slice(&value.to_ne_bytes());
        }
        if let Some(field) = self.layout.ea_size {
            self.bytes[offset + field..offset + field + 4].copy_from_slice(&0u32.to_ne_bytes());
        }
        if let Some(field) = self.layout.file_id {
            self.bytes[offset + field..offset + field + 8].copy_from_slice(&ino.to_ne_bytes());
        }
        for (index, unit) in utf16.iter().enumerate() {
            let start = offset + self.layout.name + index * 2;
            self.bytes[start..start + 2].copy_from_slice(&unit.to_ne_bytes());
        }
        self.last = Some(offset);
        true
    }
}

fn put_i64(out: &mut [u8], offset: usize, value: i64) {
    out[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
}

fn filetime(time: vfs::Timespec64) -> i64 {
    let seconds = time.sec.saturating_add(NT_FILETIME_EPOCH_SECONDS);
    seconds.saturating_mul(10_000_000).saturating_add((time.nsec / 100) as i64)
}

fn object_path(attrs: u64) -> Option<String> {
    if read_u32(attrs).ok()? < 48 || read_u64_at(attrs, 8).ok()? != 0 { return None; }
    let (_, path) = object_name(attrs)?;
    crate::nt_path::normalize_absolute_path(&path)
}

fn object_path_with_root(attrs: u64, table: &sched::nt_object::NtHandleTable) -> Option<String> {
    if read_u32(attrs).ok()? < 48 { return None; }
    let root = read_u64_at(attrs, 8).ok()?;
    let (_, raw) = object_name(attrs)?;
    let path = crate::nt_path::normalize_path(&raw)?;
    if path.starts_with('/') { return Some(path); }
    if root == 0 { return None; }
    if root > u32::MAX as u64 { return None; }
    let object = table.get(sched::nt_object::NtHandle::from_raw(root as u32), 0)?;
    let file = object.file()?;
    if file.inode().file_type() != vfs::FileType::Directory { return None; }
    let base = String::from_utf8(file.dentry().absolute_path()).ok()?;
    crate::nt_path::resolve_object_path(Some(&base), &path)
}

fn object_name(attrs: u64) -> Option<(u64, String)> {
    let name = read_u64_at(attrs, 16).ok()?;
    if name == 0 { return None; }
    let len = read_u32(name).ok()? as usize;
    if len == 0 || len > 32766 || len & 1 != 0 { return None; }
    let buffer = read_u64_at(name, 8).ok()?;
    let mut bytes = vec![0u8; len];
    uaccess::copy_from_user(&mut bytes, buffer).ok()?;
    let path = utf16_string(&bytes)?;
    Some((read_u64_at(attrs, 8).ok()?, path))
}

fn utf16_string(bytes: &[u8]) -> Option<String> {
    if bytes.len() & 1 != 0 { return None; }
    let units = bytes.chunks_exact(2)
        .map(|pair| u16::from_ne_bytes([pair[0], pair[1]]))
        .collect::<alloc::vec::Vec<_>>();
    crate::nt_path::decode_utf16(&units)
}
