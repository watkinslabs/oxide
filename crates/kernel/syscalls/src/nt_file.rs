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
const STATUS_END_OF_FILE: u64 = 0xc000_0011;
const FILE_READ_DATA: u32 = 0x0001;
const FILE_WRITE_DATA: u32 = 0x0002;
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
const FILE_LIST_DIRECTORY: u32 = 0x0001;
const FILE_APPEND_DATA: u32 = 0x0004;
const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
const FILE_GENERIC_READ: u32 = 0x0012_0089;
const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
const FILE_DIRECTORY_FILE: u32 = 0x1;
const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;
const MAX_NT_IO: usize = 16 * 1024 * 1024;
const FILE_BASIC_INFORMATION: u32 = 4;
const FILE_STANDARD_INFORMATION: u32 = 5;
const FILE_POSITION_INFORMATION: u32 = 14;
const FILE_END_OF_FILE_INFORMATION: u32 = 20;
const FILE_RENAME_INFORMATION: u32 = 10;
const FILE_DISPOSITION_INFORMATION: u32 = 13;
const DELETE_ACCESS: u32 = 0x0001_0000;
const FILE_NAMES_INFORMATION: u32 = 12;
const FILE_INTERNAL_INFORMATION: u32 = 6;
const FILE_EA_INFORMATION: u32 = 7;
const FILE_ACCESS_INFORMATION: u32 = 8;
const FILE_NAME_INFORMATION: u32 = 9;
const FILE_ALIGNMENT_INFORMATION: u32 = 17;
const FILE_ALL_INFORMATION: u32 = 18;
const FILE_NETWORK_OPEN_INFORMATION: u32 = 34;
const FILE_ATTRIBUTE_TAG_INFORMATION: u32 = 35;
const NT_FILETIME_EPOCH_SECONDS: i64 = 11_644_473_600;
const STATUS_NO_MORE_FILES: u64 = 0x8000_0006;
const STATUS_INVALID_INFO_CLASS: u64 = 0xc000_0003;
const STATUS_INFO_LENGTH_MISMATCH: u64 = 0xc000_0004;

/// Dispatch the implemented synchronous NT file operations. # C: O(path) + O(bytes)
pub fn dispatch(call: NtFileCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    match call {
        NtFileCall::QueryAttributes { attributes, information } => query_attributes(attributes.as_u64(), information.as_u64()),
        NtFileCall::QueryFullAttributes { attributes, information } => query_full_attributes(attributes.as_u64(), information.as_u64()),
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
    match call.service {
        NtService::CreateFile => Some(native_create(call)),
        NtService::OpenFile => Some(native_open(call)),
        NtService::ReadFile => Some(native_io(call, false)),
        NtService::WriteFile => Some(native_io(call, true)),
        NtService::QueryInformationFile => Some(native_query_information(call)),
        NtService::SetInformationFile => Some(native_set_information(call)),
        NtService::QueryDirectoryFile => Some(native_query_directory(call)),
        _ => None,
    }
}

fn native_create(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let Some(share) = crate::nt_dispatch::stack_argument(6) else { return STATUS_INVALID_PARAMETER; };
    let Some(disposition) = crate::nt_dispatch::stack_argument(7) else { return STATUS_INVALID_PARAMETER; };
    let Some(options) = crate::nt_dispatch::stack_argument(8) else { return STATUS_INVALID_PARAMETER; };
    if disposition > u32::MAX as u64 || share > u32::MAX as u64 || options > u32::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    let Some(disposition) = CreateDisposition::decode(disposition as u32) else { return STATUS_INVALID_PARAMETER; };
    if call.args.a0 == 0 || call.args.a2 == 0 || call.args.a1 > u32::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    let status = open_path(cur, call.args.a0, call.args.a1 as u32,
        call.args.a2, options as u32, share as u32, disposition);
    if call.args.a3 != 0 { let _ = uaccess::put_user_u64(call.args.a3, status); let _ = uaccess::put_user_u64(call.args.a3 + 8, 0); }
    status
}

fn native_open(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let options = call.args.a5;
    if call.args.a0 == 0 || call.args.a2 == 0 || call.args.a1 > u32::MAX as u64 || call.args.a4 > u32::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    let status = open_path(cur, call.args.a0, call.args.a1 as u32,
        call.args.a2, options as u32, call.args.a4 as u32, CreateDisposition::Open);
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
    native_io_values(cur, call.args.a0 as u32, call.args.a4, call.args.a5,
        length as u32, offset, write)
}

fn native_io_values(cur: &sched::Task, handle: u32, io_status: u64, buffer: u64,
                    length: u32, offset: u64, write: bool) -> u64 {
    if length as usize > MAX_NT_IO { return STATUS_INVALID_PARAMETER; }
    let required = if write { FILE_WRITE_DATA } else { FILE_READ_DATA };
    let native = sched::nt_object::NtHandle::from_raw(handle);
    let table = cur.thread_group.nt_handles();
    let Some(object) = table.get(native, required) else {
        return if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE };
    };
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
    match result {
        Ok(bytes) => { write_io_status(io_status, STATUS_SUCCESS, bytes); post_completion(&object, io_status, STATUS_SUCCESS, bytes); STATUS_SUCCESS }
        Err(_) => { write_io_status(io_status, STATUS_END_OF_FILE, 0); post_completion(&object, io_status, STATUS_END_OF_FILE, 0); STATUS_END_OF_FILE }
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

fn query_attributes(attributes: u64, information: u64) -> u64 {
    if attributes == 0 || information == 0 { return STATUS_ACCESS_VIOLATION; }
    let Some(path) = object_path(attributes) else { return STATUS_INVALID_PARAMETER; };
    let lookup = crate::pathresolve::resolve_at_path(crate::pathresolve::AT_FDCWD, &path, vfs::LookupFlags::default());
    let Ok(vp) = lookup else { return STATUS_OBJECT_NAME_NOT_FOUND; };
    let file_type = vp.inode.file_type();
    if file_type != vfs::FileType::Regular && file_type != vfs::FileType::Directory { return STATUS_INVALID_INFO_CLASS; }
    let stat = vfs::generic_fillattr(vp.inode.as_ref(), &vfs::IDENTITY);
    let mut out = [0u8; 40];
    put_i64(&mut out, 0, filetime(stat.btime.unwrap_or(stat.ctime)));
    put_i64(&mut out, 8, filetime(stat.atime));
    put_i64(&mut out, 16, filetime(stat.mtime));
    put_i64(&mut out, 24, filetime(stat.ctime));
    let file_attributes: u32 = if file_type == vfs::FileType::Directory { 0x10 } else { 0x80 };
    out[32..36].copy_from_slice(&file_attributes.to_ne_bytes());
    if uaccess::copy_to_user(information, &out).is_err() { STATUS_ACCESS_VIOLATION } else { STATUS_SUCCESS }
}

fn query_full_attributes(attributes: u64, information: u64) -> u64 {
    if attributes == 0 || information == 0 { return STATUS_ACCESS_VIOLATION; }
    let Some(path) = object_path(attributes) else { return STATUS_INVALID_PARAMETER; };
    let lookup = crate::pathresolve::resolve_at_path(crate::pathresolve::AT_FDCWD, &path, vfs::LookupFlags::default());
    let Ok(vp) = lookup else { return STATUS_OBJECT_NAME_NOT_FOUND; };
    let file_type = vp.inode.file_type();
    if file_type != vfs::FileType::Regular && file_type != vfs::FileType::Directory { return STATUS_INVALID_INFO_CLASS; }
    let stat = vfs::generic_fillattr(vp.inode.as_ref(), &vfs::IDENTITY);
    let mut out = [0u8; 56];
    put_i64(&mut out, 0, filetime(stat.btime.unwrap_or(stat.ctime)));
    put_i64(&mut out, 8, filetime(stat.atime));
    put_i64(&mut out, 16, filetime(stat.mtime));
    put_i64(&mut out, 24, filetime(stat.ctime));
    put_i64(&mut out, 32, stat.size as i64);
    put_i64(&mut out, 40, stat.size as i64);
    let file_attributes: u32 = if file_type == vfs::FileType::Directory { 0x10 } else { 0x80 };
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
        Err(error) => nt_status_from_errno(-(error as i64)),
    };
    if uaccess::put_user_u64(io_status, status).is_err()
        || uaccess::put_user_u64(io_status + 8, 0).is_err() {
        return STATUS_ACCESS_VIOLATION;
    }
    status
}

fn cancel(cur: &sched::Task, handle: u32, io: Option<u64>, io_status: u64) -> u64 {
    let table = cur.thread_group.nt_handles();
    let native = sched::nt_object::NtHandle::from_raw(handle);
    let Some(object) = table.get(native, 0) else { return STATUS_INVALID_HANDLE; };
    if object.file().is_none() { return STATUS_INVALID_HANDLE; }
    let status = if io.is_some() { STATUS_NOT_FOUND } else { STATUS_SUCCESS };
    if uaccess::put_user_u64(io_status, status).is_err() || uaccess::put_user_u64(io_status + 8, 0).is_err() { return STATUS_ACCESS_VIOLATION; }
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
    if uaccess::put_user_u64(io_status, STATUS_NOT_FOUND).is_err() || uaccess::put_user_u64(io_status + 8, 0).is_err() { return STATUS_ACCESS_VIOLATION; }
    STATUS_NOT_FOUND
}

fn read_u32(addr: u64) -> Result<u32, u64> { uaccess::get_user_u32(addr).map_err(|_| STATUS_INVALID_PARAMETER) }
fn read_u64(addr: u64) -> Result<u64, u64> { uaccess::get_user_u64(addr).map_err(|_| STATUS_INVALID_PARAMETER) }

fn open_create(cur: &sched::Task, addr: u64) -> u64 {
    let request = match (read_u64(addr), read_u32(addr + 8), read_u64(addr + 16),
        read_u64(addr + 24), read_u32(addr + 32), read_u32(addr + 36),
        read_u32(addr + 40), read_u32(addr + 44)) {
        (Ok(handle), Ok(desired_access), Ok(object_attributes), Ok(allocation_size),
         Ok(file_attributes), Ok(share_access), Ok(disposition), Ok(options)) =>
            NtCreateFileRequest { handle, desired_access, object_attributes, allocation_size,
                file_attributes, share_access, disposition, options },
        _ => return STATUS_INVALID_PARAMETER,
    };
    if request.handle == 0 || request.object_attributes == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(disposition) = CreateDisposition::decode(request.disposition) else { return STATUS_INVALID_PARAMETER; };
    open_path(cur, request.handle, request.desired_access, request.object_attributes,
        request.options, request.share_access, disposition)
}

fn open_existing(cur: &sched::Task, addr: u64, _create: bool) -> u64 {
    let request = match (read_u64(addr), read_u32(addr + 8), read_u64(addr + 16),
        read_u32(addr + 24), read_u32(addr + 28)) {
        (Ok(handle), Ok(desired_access), Ok(object_attributes), Ok(share_access), Ok(options)) =>
            NtOpenFileRequest { handle, desired_access, object_attributes, share_access, options },
        _ => return STATUS_INVALID_PARAMETER,
    };
    if request.handle == 0 || request.object_attributes == 0 { return STATUS_INVALID_PARAMETER; }
    open_path(cur, request.handle, request.desired_access, request.object_attributes, request.options, request.share_access, CreateDisposition::Open)
}

fn open_path(cur: &sched::Task, output: u64, desired: u32, attrs: u64, options: u32, sharing: u32, disposition: CreateDisposition) -> u64 {
    if sharing & !0x7 != 0 { return STATUS_INVALID_PARAMETER; }
    let Some(path) = object_path(attrs) else { return STATUS_INVALID_PARAMETER; };
    let wants_write = desired & (GENERIC_WRITE | FILE_GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA) != 0;
    let wants_read = desired & (GENERIC_READ | FILE_GENERIC_READ | FILE_READ_DATA) != 0;
    if !wants_read && !wants_write { return STATUS_ACCESS_DENIED; }
    let mut flags = if wants_write {
        if desired & FILE_APPEND_DATA != 0 { vfs::OpenFlags::O_APPEND } else { vfs::OpenFlags::O_RDWR }
    } else { vfs::OpenFlags::O_RDONLY };
    if options & FILE_DIRECTORY_FILE != 0 { flags |= vfs::OpenFlags::O_DIRECTORY; }
    if options & FILE_NON_DIRECTORY_FILE != 0 && path.ends_with('/') { return STATUS_INVALID_PARAMETER; }
    let lookup = crate::pathresolve::resolve_at_path(crate::pathresolve::AT_FDCWD, &path, vfs::LookupFlags::default());
    let (inode, dentry, mnt_id, created) = match lookup {
        Ok(_vp) if disposition.rejects_existing() => return STATUS_OBJECT_NAME_COLLISION,
        Ok(vp) => (vp.inode, vp.dentry, vp.mnt_id, false),
        Err(rv) if disposition.allows_missing() && rv == -(Errno::Enoent.as_i32() as i64) => {
            let mut parent_flags = vfs::LookupFlags::default();
            parent_flags.parent = true;
            let Ok(parent) = crate::pathresolve::resolve_parent_at_flags(crate::pathresolve::AT_FDCWD, &path, parent_flags) else {
                return STATUS_OBJECT_NAME_NOT_FOUND;
            };
            let Some(name) = parent.last_component.clone() else { return STATUS_INVALID_PARAMETER; };
            let ctx = vfs::CreateCtx { idmap: &vfs::IDENTITY, cred: &crate::pathresolve::current_cred(), umask: cur.umask() as u16 };
            match vfs::vfs_create_at(&parent, &name, 0o666, &ctx) {
                Ok((inode, dentry)) => (inode, dentry, parent.mnt_id, true),
                Err(error) => return nt_status_from_errno(-(error as i64)),
            }
        }
        Err(rv) => return nt_status_from_errno(rv),
    };
    if let Some(rv) = crate::open_common::enforce_open_perm(&inode, mnt_id, flags.bits(), created) {
        return nt_status_from_errno(rv);
    }
    if !created && disposition.truncates_existing() && inode.truncate(0).is_err() {
        return STATUS_ACCESS_DENIED;
    }
    let Some(cred) = crate::pathresolve::file_cred_for(cur) else { return STATUS_ACCESS_DENIED; };
    let Ok(file) = vfs::file::open_file_at(inode, dentry, flags, mnt_id, cred, None) else {
        return STATUS_ACCESS_DENIED;
    };
    let delete = if options & FILE_DELETE_ON_CLOSE != 0 {
        if !crate::nt_file_policy::delete_on_close_access_valid(options, desired) { return STATUS_INVALID_PARAMETER; }
        if sched::nt_object::NtDeleteOnClose::new(file.as_ref(), false).is_none() { return STATUS_INVALID_PARAMETER; }
        true
    } else { false };
    let table = cur.thread_group.nt_handles();
    let Some(share) = sched::nt_object::NtFileShare::claim(&file, desired, sharing) else {
        return STATUS_SHARING_VIOLATION;
    };
    let object = table.new_file_with_share_and_delete(file, share, delete);
    let Some(handle) = table.insert(object, desired | SYNCHRONIZE_ACCESS) else {
        return STATUS_INVALID_PARAMETER;
    };
    if uaccess::put_user_u32(output, handle.raw()).is_err() {
        let _ = table.close(handle);
        return STATUS_INVALID_PARAMETER;
    }
    STATUS_SUCCESS
}

fn io(cur: &sched::Task, addr: u64, write: bool) -> u64 {
    let request = match (read_u32(addr), read_u32(addr + 4), read_u64(addr + 8),
        read_u64(addr + 16), read_u32(addr + 24), read_u64(addr + 32)) {
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
        Ok(bytes) => {
            write_io_status(request.io_status, STATUS_SUCCESS, bytes);
            post_completion(&object, request.io_status, STATUS_SUCCESS, bytes);
            STATUS_SUCCESS
        }
        Err(_) => {
            write_io_status(request.io_status, STATUS_END_OF_FILE, 0);
            post_completion(&object, request.io_status, STATUS_END_OF_FILE, 0);
            STATUS_END_OF_FILE
        }
    }
}

fn write_io_status(addr: u64, status: u64, information: u64) {
    let _ = uaccess::put_user_u64(addr, status);
    let _ = uaccess::put_user_u64(addr + 8, information);
}

fn post_completion(object: &sched::nt_object::NtObject, overlapped: u64, status: u64, information: u64) {
    let Some((port, key)) = object.file_completion() else { return; };
    port.post(sched::nt_object::NtCompletionPacket { key, overlapped, status: status as u32, information });
}

fn query_information(cur: &sched::Task, addr: u64) -> u64 {
    let (handle, io_status, information, length, class) = match (
        read_u32(addr), read_u64(addr + 8), read_u64(addr + 16),
        read_u32(addr + 24), read_u32(addr + 28)) {
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
    let Some(file) = object.file() else { return STATUS_INVALID_HANDLE; };
    let stat = vfs::generic_fillattr(file.inode(), &vfs::IDENTITY);
    let is_directory = file.inode().file_type() == vfs::FileType::Directory;
    let file_attributes: u32 = if is_directory { 0x10 } else { 0x80 };
    let path = String::from_utf8(file.dentry().absolute_path()).ok();
    let name: alloc::vec::Vec<u16> = path.as_deref().unwrap_or("").encode_utf16().collect();
    let name_bytes = name.len().saturating_mul(2);
    let all_size = 100usize.saturating_add(name_bytes);
    let mut out = alloc::vec::Vec::new();
    let needed = match class {
        FILE_BASIC_INFORMATION => {
            out.resize(40, 0);
            put_i64(&mut out, 0, filetime(stat.btime.unwrap_or(stat.ctime)));
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
        FILE_ACCESS_INFORMATION => { out.resize(4, 0); 4 }
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
            put_i64(&mut out, 0, filetime(stat.btime.unwrap_or(stat.ctime)));
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
            put_i64(&mut out, 0, filetime(stat.btime.unwrap_or(stat.ctime)));
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
    let (handle, io_status, information, length, class) = match (
        read_u32(addr), read_u64(addr + 8), read_u64(addr + 16),
        read_u32(addr + 24), read_u32(addr + 28)) {
        (Ok(handle), Ok(io_status), Ok(information), Ok(length), Ok(class)) =>
            (handle, io_status, information, length, class),
        _ => return STATUS_INVALID_PARAMETER,
    };
    set_information_values(cur, handle, io_status, information, length, class)
}

fn set_information_values(cur: &sched::Task, handle: u32, io_status: u64, information: u64, length: u32, class: u32) -> u64 {
    if io_status == 0 || information == 0 || (class != FILE_DISPOSITION_INFORMATION && length < 8) { return STATUS_INVALID_PARAMETER; }
    let native = sched::nt_object::NtHandle::from_raw(handle);
    let table = cur.thread_group.nt_handles();
    let required = if class == FILE_DISPOSITION_INFORMATION { DELETE_ACCESS } else { FILE_WRITE_DATA };
    let Some(object) = table.get(native, required) else {
        return if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE };
    };
    let Some(file) = object.file() else { return STATUS_INVALID_HANDLE; };
    if class == FILE_RENAME_INFORMATION { return set_rename_information(file.as_ref(), information, length, io_status); }
    if class == FILE_DISPOSITION_INFORMATION {
        let Ok(delete) = read_u32(information) else { return STATUS_INVALID_PARAMETER; };
        let Some(state) = object.delete_on_close() else { return STATUS_INVALID_PARAMETER; };
        if delete > 1 { return STATUS_INVALID_PARAMETER; }
        state.set_armed(delete != 0);
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
    let Ok(root) = read_u64(information + 8) else { return STATUS_INVALID_PARAMETER; };
    let Ok(name_len) = read_u32(information + 16) else { return STATUS_INVALID_PARAMETER; };
    let name_len = name_len as usize;
    if replace > 1 || root != 0 || name_len == 0 || name_len & 1 != 0
        || name_len > length - RENAME_HEADER_BYTES || name_len > 32766 { return STATUS_INVALID_PARAMETER; }
    let mut bytes = vec![0u8; name_len];
    if uaccess::copy_from_user(&mut bytes, information + RENAME_HEADER_BYTES as u64).is_err() { return STATUS_INVALID_PARAMETER; }
    let Some(raw_target) = utf16_string(&bytes) else { return STATUS_INVALID_PARAMETER; };
    let Some(target) = crate::nt_path::normalize_path(&raw_target) else { return STATUS_INVALID_PARAMETER; };
    let source = vfs::path_from_bytes(&file.dentry().absolute_path());
    let flags = if replace == 0 { vfs::namei::RENAME_NOREPLACE } else { 0 };
    let status = crate::s082_rename::rename_kernel_paths(&source, &target, flags);
    if status == 0 {
        write_io_status(io_status, STATUS_SUCCESS, 0);
        STATUS_SUCCESS
    } else { nt_status_from_errno(status) }
}

fn query_directory(cur: &sched::Task, addr: u64) -> u64 {
    let (handle, io_status, information, length, class) = match (
        read_u32(addr), read_u64(addr + 8), read_u64(addr + 16),
        read_u32(addr + 24), read_u32(addr + 28)) {
        (Ok(handle), Ok(io_status), Ok(information), Ok(length), Ok(class)) =>
            (handle, io_status, information, length, class),
        _ => return STATUS_INVALID_PARAMETER,
    };
    query_directory_values(cur, handle, io_status, information, length, class)
}

fn query_directory_values(cur: &sched::Task, handle: u32, io_status: u64, information: u64, length: u32, class: u32) -> u64 {
    if io_status == 0 || information == 0 || class != FILE_NAMES_INFORMATION || length == 0 {
        return STATUS_INVALID_PARAMETER;
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
    let mut emitter = NameEmitter::new(length as usize);
    let (result, next_pos) = vfs::readdir_dots(file.as_ref(), file.inode().ino(), parent_ino,
        file.pos(), &mut emitter);
    if result.is_err() { return STATUS_INVALID_PARAMETER; }
    if emitter.bytes.is_empty() {
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
}

impl NameEmitter {
    fn new(capacity: usize) -> Self { Self { bytes: alloc::vec::Vec::new(), capacity, last: None } }
}

impl vfs::DirEmit for NameEmitter {
    fn emit(&mut self, name: &str, _ino: u64, _kind: vfs::FileType, _next_pos: u64) -> bool {
        let utf16: alloc::vec::Vec<u16> = name.encode_utf16().collect();
        let name_bytes = utf16.len().saturating_mul(2);
        let record_len = (12usize).saturating_add(name_bytes);
        let aligned = (record_len + 7) & !7;
        if aligned > self.capacity.saturating_sub(self.bytes.len()) { return false; }
        let offset = self.bytes.len();
        if let Some(last) = self.last {
            let delta = (offset - last) as u32;
            self.bytes[last..last + 4].copy_from_slice(&delta.to_ne_bytes());
        }
        self.bytes.resize(offset + aligned, 0);
        self.bytes[offset + 4..offset + 8].copy_from_slice(&0u32.to_ne_bytes());
        self.bytes[offset + 8..offset + 12].copy_from_slice(&(name_bytes as u32).to_ne_bytes());
        for (index, unit) in utf16.iter().enumerate() {
            let start = offset + 12 + index * 2;
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
    if read_u32(attrs).ok()? < 48 || read_u64(attrs + 8).ok()? != 0 { return None; }
    let name = read_u64(attrs + 16).ok()?;
    if name == 0 { return None; }
    let len = read_u32(name).ok()? as usize;
    if len == 0 || len > 32766 || len & 1 != 0 { return None; }
    let buffer = read_u64(name + 8).ok()?;
    let mut bytes = vec![0u8; len];
    uaccess::copy_from_user(&mut bytes, buffer).ok()?;
    let path = utf16_string(&bytes)?;
    crate::nt_path::normalize_path(&path)
}

fn utf16_string(bytes: &[u8]) -> Option<String> {
    if bytes.len() & 1 != 0 { return None; }
    let mut out = String::new();
    for pair in bytes.chunks_exact(2) {
        let c = u16::from_ne_bytes([pair[0], pair[1]]);
        out.push(core::char::from_u32(c as u32)?);
    }
    Some(out)
}

fn nt_status_from_errno(rv: i64) -> u64 {
    match rv.unsigned_abs() as i32 {
        x if x == Errno::Enoent.as_i32() => STATUS_OBJECT_NAME_NOT_FOUND,
        x if x == Errno::Eexist.as_i32() => STATUS_OBJECT_NAME_COLLISION,
        x if x == Errno::Eacces.as_i32() => STATUS_ACCESS_DENIED,
        _ => STATUS_INVALID_PARAMETER,
    }
}
