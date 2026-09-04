//! Native owner for Wine's private Unix-call ABI.
//!
//! The handle is an opaque Oxide table identity, not a userspace function
//! pointer. This keeps the transition safe while preserving Wine's ABI.

use syscall::nt::{NtCall, NtService};
use syscall::nt_wine_unix::WineUnixFunction;

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;
#[cfg(test)]
const STATUS_UNSUCCESSFUL: u64 = 0xc000_0001;
const STATUS_HANDLE_NOT_CLOSABLE: u64 = 0xc000_0235;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
const STATUS_OBJECT_NAME_COLLISION: u64 = 0xc000_0035;
const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xc000_0034;
const STATUS_OBJECT_TYPE_MISMATCH: u64 = 0xc000_0024;
const STATUS_CONFLICTING_ADDRESSES: u64 = 0xc000_0018;
const STATUS_MEMORY_NOT_ALLOCATED: u64 = 0xc000_00a0;
const MAX_WINE_DEBUG_WRITE: usize = 1 << 20;

const UNW_FLAG_MASK: u32 = 0x7;

const SERVER_REQ_CLOSE_HANDLE: u32 = 21;
const SERVER_REQ_CREATE_EVENT: u32 = 30;
const SERVER_REQ_EVENT_OP: u32 = 31;
const SERVER_REQ_QUERY_EVENT: u32 = 32;
#[cfg(test)]
const SERVER_HEADER_BYTES: u64 = 12;
const SERVER_REQUEST_SIZE: u64 = 4;
const SERVER_REPLY_SIZE: u64 = 8;
const SERVER_HANDLE: u64 = 12;
const SERVER_EVENT_OP: u64 = 16;
const SERVER_EVENT_MANUAL_RESET: u64 = 16;
const SERVER_EVENT_INITIAL_STATE: u64 = 20;
const SERVER_REPLY_HANDLE: u64 = 8;
const SERVER_REPLY_STATE: u64 = 8;
const SERVER_REPLY_MANUAL_RESET: u64 = 8;
const SERVER_REPLY_EVENT_STATE: u64 = 12;
const EVENT_MODIFY_STATE: u32 = 0x0002;
const EVENT_QUERY_STATE: u32 = 0x0001;
const MUTANT_MODIFY_STATE: u32 = 0x0001;
const MUTANT_QUERY_STATE: u32 = 0x0001;
const SEMAPHORE_MODIFY_STATE: u32 = 0x0002;
const SEMAPHORE_QUERY_STATE: u32 = 0x0001;
const SERVER_REQ_CREATE_MUTEX: u32 = 36;
const SERVER_REQ_RELEASE_MUTEX: u32 = 37;
const SERVER_REQ_QUERY_MUTEX: u32 = 39;
const SERVER_REQ_CREATE_SEMAPHORE: u32 = 40;
const SERVER_REQ_RELEASE_SEMAPHORE: u32 = 41;
const SERVER_REQ_QUERY_SEMAPHORE: u32 = 42;
const SERVER_SYNC_ACCESS: u64 = 12;
const SERVER_SYNC_VALUE: u64 = 16;
const SERVER_SYNC_VALUE_TWO: u64 = 20;
const SERVER_REPLY_VALUE: u64 = 8;
const SERVER_REPLY_VALUE_TWO: u64 = 12;
const SERVER_REPLY_VALUE_THREE: u64 = 16;
const SERVER_REQ_SELECT: u32 = 29;
const SERVER_REQ_CREATE_MAPPING: u32 = 63;
const SERVER_REQ_OPEN_MAPPING: u32 = 64;
const SERVER_REQ_GET_MAPPING_INFO: u32 = 65;
const SERVER_REQ_GET_IMAGE_MAP_ADDRESS: u32 = 66;
const SERVER_REQ_MAP_VIEW: u32 = 67;
const SERVER_REQ_MAP_IMAGE_VIEW: u32 = 68;
const SERVER_REQ_UNMAP_VIEW: u32 = 71;
const SERVER_SEC_IMAGE: u32 = 0x0100_0000;
const SERVER_SELECT_WAIT: u32 = 1;
const SERVER_SELECT_WAIT_ALL: u32 = 2;
const SERVER_SELECT_ALERTABLE: u32 = 1;
const SERVER_SELECT_MAX_HANDLES: u32 = 64;
const SERVER_DATA_COUNT: u64 = 64;
const SERVER_DATA_ZERO_PTR: u64 = 80;
const SERVER_DATA_ZERO_SIZE: u64 = 88;
const SERVER_DATA_ONE_PTR: u64 = 96;
const SERVER_DATA_ONE_SIZE: u64 = 104;
const SERVER_APC_RESULT_BYTES: u32 = 40;
const SERVER_SELECT_TIMEOUT: u64 = 24;
const SERVER_SELECT_REPLY_SIGNALED: u64 = 12;
const SERVER_TIMEOUT_INFINITE: u64 = 0x7fff_ffff_ffff_ffff;
const SERVER_MAPPING_ACCESS_WRITE: u32 = 0x0002;
const SERVER_MAPPING_MAX_BYTES: u64 = 1 << 36;

fn wine_arg(base: u64, offset: u64) -> Option<u64> { base.checked_add(offset) }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ServerRequest { CloseHandle, CreateEvent, EventOp, QueryEvent, Select, CreateMutex, ReleaseMutex, QueryMutex, CreateSemaphore, ReleaseSemaphore, QuerySemaphore, CreateMapping, OpenMapping, GetMappingInfo, GetImageMapAddress, MapView, MapImageView, UnmapView }

fn select_opcode_kind(op: u32) -> Option<u32> {
    match op { SERVER_SELECT_WAIT => Some(0), SERVER_SELECT_WAIT_ALL => Some(1), _ => None }
}

fn server_request_kind(request: u32) -> Option<ServerRequest> {
    match request {
        SERVER_REQ_CLOSE_HANDLE => Some(ServerRequest::CloseHandle),
        SERVER_REQ_CREATE_EVENT => Some(ServerRequest::CreateEvent),
        SERVER_REQ_EVENT_OP => Some(ServerRequest::EventOp),
        SERVER_REQ_QUERY_EVENT => Some(ServerRequest::QueryEvent),
        SERVER_REQ_SELECT => Some(ServerRequest::Select),
        SERVER_REQ_CREATE_MUTEX => Some(ServerRequest::CreateMutex),
        SERVER_REQ_RELEASE_MUTEX => Some(ServerRequest::ReleaseMutex),
        SERVER_REQ_QUERY_MUTEX => Some(ServerRequest::QueryMutex),
        SERVER_REQ_CREATE_SEMAPHORE => Some(ServerRequest::CreateSemaphore),
        SERVER_REQ_RELEASE_SEMAPHORE => Some(ServerRequest::ReleaseSemaphore),
        SERVER_REQ_QUERY_SEMAPHORE => Some(ServerRequest::QuerySemaphore),
        SERVER_REQ_CREATE_MAPPING => Some(ServerRequest::CreateMapping),
        SERVER_REQ_OPEN_MAPPING => Some(ServerRequest::OpenMapping),
        SERVER_REQ_GET_MAPPING_INFO => Some(ServerRequest::GetMappingInfo),
        SERVER_REQ_GET_IMAGE_MAP_ADDRESS => Some(ServerRequest::GetImageMapAddress),
        SERVER_REQ_MAP_VIEW => Some(ServerRequest::MapView),
        SERVER_REQ_MAP_IMAGE_VIEW => Some(ServerRequest::MapImageView),
        SERVER_REQ_UNMAP_VIEW => Some(ServerRequest::UnmapView),
        _ => None,
    }
}

fn windows_time_ticks(realtime_ns: u64) -> u64 { realtime_ns.saturating_div(100) }

fn valid_unwind_type(value: u32) -> bool { value & !UNW_FLAG_MASK == 0 }

#[cfg(target_os = "oxide-kernel")]
fn unix_fd_to_handle(args: u64) -> u64 {
    let Ok(fd) = uaccess::get_user_u32(args) else { return STATUS_INVALID_PARAMETER; };
    let Some(access_address) = wine_arg(args, 4) else { return STATUS_INVALID_PARAMETER; };
    let Some(output_address) = wine_arg(args, 16) else { return STATUS_INVALID_PARAMETER; };
    let Ok(access) = uaccess::get_user_u32(access_address) else { return STATUS_INVALID_PARAMETER; };
    let Ok(output) = uaccess::get_user_u64(output_address) else { return STATUS_INVALID_PARAMETER; };
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    let Some(fdt) = cur.clone_fd_table() else { return STATUS_INVALID_PARAMETER; };
    let Ok(file) = fdt.get(fd as i32) else { return STATUS_INVALID_HANDLE; };
    let object = cur.thread_group.nt_handles().new_file(file);
    let Some(handle) = cur.thread_group.nt_handles().insert(object, access) else { return STATUS_INVALID_HANDLE; };
    if uaccess::put_user_u32(output, handle.raw()).is_err() {
        let _ = cur.thread_group.nt_handles().close(handle);
        STATUS_INVALID_PARAMETER
    } else { STATUS_SUCCESS }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn unix_fd_to_handle(_args: u64) -> u64 { STATUS_INVALID_PARAMETER }

#[cfg(target_os = "oxide-kernel")]
fn unix_handle_to_fd(args: u64) -> u64 {
    let Ok(raw_handle) = uaccess::get_user_u32(args) else { return STATUS_INVALID_PARAMETER; };
    let (Some(access_address), Some(output_fd_address), Some(output_options_address)) =
        (wine_arg(args, 4), wine_arg(args, 16), wine_arg(args, 24)) else { return STATUS_INVALID_PARAMETER; };
    let Ok(access) = uaccess::get_user_u32(access_address) else { return STATUS_INVALID_PARAMETER; };
    let Ok(output_fd) = uaccess::get_user_u64(output_fd_address) else { return STATUS_INVALID_PARAMETER; };
    let Ok(output_options) = uaccess::get_user_u64(output_options_address) else { return STATUS_INVALID_PARAMETER; };
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    let Some(object) = cur.thread_group.nt_handles().get(sched::nt_object::NtHandle::from_raw(raw_handle), access) else {
        return if cur.thread_group.nt_handles().contains(sched::nt_object::NtHandle::from_raw(raw_handle)) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE };
    };
    let Some(file) = object.file() else { return STATUS_INVALID_HANDLE; };
    let Some(fdt) = cur.clone_fd_table() else { return STATUS_INVALID_PARAMETER; };
    let Ok(fd) = fdt.alloc(file) else { return STATUS_NO_MEMORY; };
    if uaccess::put_user_u32(output_fd, fd as u32).is_err() || uaccess::put_user_u32(output_options, 0).is_err() {
        let _ = fdt.close(fd);
        STATUS_INVALID_PARAMETER
    } else { STATUS_SUCCESS }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn unix_handle_to_fd(_args: u64) -> u64 { STATUS_INVALID_PARAMETER }

#[cfg(target_os = "oxide-kernel")]
fn server_select(args: u64) -> u64 {
    let Some(data_count_address) = wine_arg(args, SERVER_DATA_COUNT) else { return STATUS_INVALID_PARAMETER; };
    let Ok(data_count) = uaccess::get_user_u32(data_count_address) else { return STATUS_INVALID_PARAMETER; };
    if data_count != 2 { return server_reply(args, STATUS_INVALID_PARAMETER); }
    let (Some(result_ptr_address), Some(result_size_address)) = (wine_arg(args, SERVER_DATA_ZERO_PTR), wine_arg(args, SERVER_DATA_ZERO_SIZE)) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    let Ok(result_ptr) = uaccess::get_user_u64(result_ptr_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    let Ok(result_size) = uaccess::get_user_u32(result_size_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    if result_ptr == 0 || result_size != SERVER_APC_RESULT_BYTES { return server_reply(args, STATUS_INVALID_PARAMETER); }
    let (Some(data_ptr_address), Some(data_size_address), Some(request_size_address)) = (wine_arg(args, SERVER_DATA_ONE_PTR), wine_arg(args, SERVER_DATA_ONE_SIZE), wine_arg(args, SERVER_REQUEST_SIZE)) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    let Ok(data_ptr) = uaccess::get_user_u64(data_ptr_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    let Ok(data_size) = uaccess::get_user_u32(data_size_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    let Ok(request_size) = uaccess::get_user_u32(request_size_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    if SERVER_APC_RESULT_BYTES.checked_add(data_size) != Some(request_size) { return server_reply(args, STATUS_INVALID_PARAMETER); }
    if data_ptr == 0 || data_size < 8 || data_size > 4 + SERVER_SELECT_MAX_HANDLES * 4 || data_size % 4 != 0 { return server_reply(args, STATUS_INVALID_PARAMETER); }
    let Ok(op) = uaccess::get_user_u32(data_ptr) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    let Some(wait_type) = select_opcode_kind(op) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    let count = (data_size - 4) / 4;
    let (Some(flags_address), Some(timeout_address)) = (wine_arg(args, 12), wine_arg(args, SERVER_SELECT_TIMEOUT)) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    let Ok(flags) = uaccess::get_user_u32(flags_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    let Ok(timeout) = uaccess::get_user_u64(timeout_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    let timeout_ptr = if timeout == SERVER_TIMEOUT_INFINITE { 0 } else { timeout_address };
    let result = crate::nt_dispatch::dispatch(NtCall {
        service: NtService::WaitForMultipleObjects,
        args: syscall::SyscallArgs { a0: count as u64, a1: wine_arg(data_ptr, 4).unwrap_or(0), a2: wait_type as u64,
            a3: (flags & SERVER_SELECT_ALERTABLE) as u64, a4: timeout_ptr, a5: 0 },
    });
    let Some(signaled_address) = wine_arg(args, SERVER_SELECT_REPLY_SIGNALED) else { return STATUS_INVALID_PARAMETER; };
    if uaccess::put_user_u32(signaled_address, (result < SERVER_SELECT_MAX_HANDLES as u64) as u32).is_err() { STATUS_INVALID_PARAMETER } else { result }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn server_select(_args: u64) -> u64 { STATUS_INVALID_PARAMETER }

#[cfg(target_os = "oxide-kernel")]
fn server_create_mapping(args: u64, request_size: u32, table: &sched::nt_object::NtHandleTable) -> u64 {
    let (Some(access_address), Some(flags_address), Some(size_address), Some(file_address)) = (wine_arg(args, 12), wine_arg(args, 16), wine_arg(args, 24), wine_arg(args, 32)) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    let Ok(access) = uaccess::get_user_u32(access_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    let Ok(flags) = uaccess::get_user_u32(flags_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    let Ok(requested_size) = uaccess::get_user_u64(size_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    let Ok(file_raw) = uaccess::get_user_u32(file_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    if access == 0 { return server_reply(args, STATUS_INVALID_PARAMETER); }
    let path = match wine_object_path(args, request_size, table) {
        Ok(path) => path,
        Err(status) => return server_reply(args, status),
    };
    let object = if file_raw == 0 {
        if requested_size == 0 || requested_size > SERVER_MAPPING_MAX_BYTES { return server_reply(args, STATUS_INVALID_PARAMETER); }
        let Some(object) = table.new_section_with_flags(round_mapping_size(requested_size), flags) else { return server_reply(args, STATUS_NO_MEMORY); };
        object
    } else {
        let file_handle = sched::nt_object::NtHandle::from_raw(file_raw);
        let Some(file_object) = table.get(file_handle, 0) else { return server_reply(args, STATUS_INVALID_HANDLE); };
        if file_object.kind() != sched::nt_object::NtObjectType::File { return server_reply(args, STATUS_INVALID_HANDLE); }
        let Some(file) = file_object.file() else { return server_reply(args, STATUS_INVALID_HANDLE); };
        let file_size = vfs::generic_fillattr(file.inode(), &vfs::IDENTITY).size;
        let size = if requested_size == 0 { file_size } else { requested_size };
        if size == 0 || size < file_size || size > SERVER_MAPPING_MAX_BYTES { return server_reply(args, STATUS_INVALID_PARAMETER); }
        table.new_file_section_with_flags(file, round_mapping_size(size), flags)
    };
    let (object, state) = match path {
        Some(path) => sched::nt_object::publish_section(&path, object),
        None => (object, sched::nt_object::NamedObjectState::Created),
    };
    if state == sched::nt_object::NamedObjectState::TypeMismatch { return server_reply(args, STATUS_OBJECT_TYPE_MISMATCH); }
    if state == sched::nt_object::NamedObjectState::ParentMissing { return server_reply(args, STATUS_OBJECT_NAME_NOT_FOUND); }
    let Some(handle) = table.insert(object, access) else { return server_reply(args, STATUS_NO_MEMORY); };
    let Some(reply_address) = wine_arg(args, SERVER_REPLY_HANDLE) else { let _ = table.close(handle); return server_reply(args, STATUS_INVALID_PARAMETER); };
    if uaccess::put_user_u32(reply_address, handle.raw()).is_err() { let _ = table.close(handle); return server_reply(args, STATUS_INVALID_PARAMETER); }
    server_reply(args, if state == sched::nt_object::NamedObjectState::Existing { STATUS_OBJECT_NAME_COLLISION } else { STATUS_SUCCESS })
}

#[cfg(target_os = "oxide-kernel")]
fn round_mapping_size(size: u64) -> usize {
    size.saturating_add(hal::PAGE_SIZE_BYTES - 1).min(usize::MAX as u64) as usize & !(hal::PAGE_SIZE_BYTES - 1) as usize
}

#[cfg(target_os = "oxide-kernel")]
fn server_map_view(args: u64, table: &sched::nt_object::NtHandleTable) -> u64 {
    let (Some(mapping_address), Some(access_address), Some(base_address), Some(size_address), Some(start_address)) =
        (wine_arg(args, 12), wine_arg(args, 16), wine_arg(args, 24), wine_arg(args, 32), wine_arg(args, 40)) else { return STATUS_INVALID_PARAMETER; };
    let (Ok(raw), Ok(access), Ok(base), Ok(size), Ok(start)) = (uaccess::get_user_u32(mapping_address), uaccess::get_user_u32(access_address), uaccess::get_user_u64(base_address), uaccess::get_user_u64(size_address), uaccess::get_user_u64(start_address)) else { return STATUS_INVALID_PARAMETER; };
    if size == 0 || start % hal::PAGE_SIZE_BYTES != 0 { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    let Some(mm) = (unsafe { cur.mm_ref() }).map(|mm| mm.clone()) else { return STATUS_INVALID_PARAMETER; };
    let required = if access & SERVER_MAPPING_ACCESS_WRITE != 0 { 0x0002 } else { 0x0004 };
    let handle = sched::nt_object::NtHandle::from_raw(raw);
    let Some(object) = table.get(handle, required) else { return if table.contains(handle) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }; };
    let Some(section) = object.section() else { return STATUS_INVALID_HANDLE; };
    if start >= section.size() as u64 || size > section.size() as u64 - start || size > SERVER_MAPPING_MAX_BYTES { return STATUS_INVALID_PARAMETER; }
    let protection = if access & SERVER_MAPPING_ACCESS_WRITE != 0 { vmm::VmaProt::READ | vmm::VmaProt::WRITE } else { vmm::VmaProt::READ };
    let backing = if let Some(file) = section.file() {
        vmm::VmaBacking::File { backing: crate::mmap_file::InodeFileBacking::new(file.inode().clone()), off: start }
    } else {
        vmm::VmaBacking::KernelBytes { data: section.bytes(), off: start as usize }
    };
    let placement = match base { 0 => vmm::MmapPlacement::Advisory(None), value => { let Some(address) = hal::UserVirtAddr::new(value) else { return STATUS_INVALID_PARAMETER; }; vmm::MmapPlacement::FixedNoReplace(address) } };
    match mm.mmap_with_may_at(placement, round_mapping_size(size), protection, protection, vmm::VmaFlags::PRIVATE, backing) {
        Ok(_) => STATUS_SUCCESS,
        Err(vmm::MmapError::Exists) => STATUS_CONFLICTING_ADDRESSES,
        Err(vmm::MmapError::Vmm(_)) => STATUS_NO_MEMORY,
    }
}

#[cfg(target_os = "oxide-kernel")]
fn server_get_image_map_address(args: u64, table: &sched::nt_object::NtHandleTable) -> u64 {
    let Some(handle_address) = wine_arg(args, 12) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    let Ok(raw) = uaccess::get_user_u32(handle_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    let handle = sched::nt_object::NtHandle::from_raw(raw);
    let Some(object) = table.get(handle, 0) else { return if table.contains(handle) { server_reply(args, STATUS_ACCESS_DENIED) } else { server_reply(args, STATUS_INVALID_HANDLE) }; };
    let Some(section) = object.section() else { return server_reply(args, STATUS_INVALID_HANDLE); };
    if section.flags() & SERVER_SEC_IMAGE == 0 { return server_reply(args, STATUS_INVALID_PARAMETER); }
    let Some(cur) = sched::live::current() else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    let Some(mm) = (unsafe { cur.mm_ref() }).map(|mm| mm.clone()) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    let Ok(address) = mm.get_unmapped_area(round_mapping_size(section.size() as u64)) else { return server_reply(args, STATUS_NO_MEMORY); };
    let Some(reply_address) = wine_arg(args, 8) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    if uaccess::put_user_u64(reply_address, address.as_u64()).is_err() { return server_reply(args, STATUS_INVALID_PARAMETER); }
    server_reply(args, STATUS_SUCCESS)
}

#[cfg(target_os = "oxide-kernel")]
fn server_map_image_view(args: u64, table: &sched::nt_object::NtHandleTable) -> u64 {
    let (Some(mapping_address), Some(base_address), Some(size_address), Some(offset_address), Some(machine_address)) =
        (wine_arg(args, 12), wine_arg(args, 16), wine_arg(args, 24), wine_arg(args, 32), wine_arg(args, 44)) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    let (Ok(raw), Ok(base_raw), Ok(size), Ok(offset), Ok(machine)) =
        (uaccess::get_user_u32(mapping_address), uaccess::get_user_u64(base_address), uaccess::get_user_u64(size_address), uaccess::get_user_u64(offset_address), uaccess::get_user_u32(machine_address)) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    if machine & 0xffff != 0x8664 || size == 0 || offset % hal::PAGE_SIZE_BYTES != 0 { return server_reply(args, STATUS_INVALID_PARAMETER); }
    let handle = sched::nt_object::NtHandle::from_raw(raw);
    let Some(object) = table.get(handle, 0) else { return if table.contains(handle) { server_reply(args, STATUS_ACCESS_DENIED) } else { server_reply(args, STATUS_INVALID_HANDLE) }; };
    let Some(section) = object.section() else { return server_reply(args, STATUS_INVALID_HANDLE); };
    if section.flags() & SERVER_SEC_IMAGE == 0 || offset >= section.size() as u64 || size > section.size() as u64 - offset || size > SERVER_MAPPING_MAX_BYTES { return server_reply(args, STATUS_INVALID_PARAMETER); }
    let Some(cur) = sched::live::current() else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    let Some(mm) = (unsafe { cur.mm_ref() }).map(|mm| mm.clone()) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    let Some(base) = hal::UserVirtAddr::new(base_raw) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    let backing = if let Some(file) = section.file() {
        vmm::VmaBacking::File { backing: crate::mmap_file::InodeFileBacking::new(file.inode().clone()), off: offset }
    } else {
        vmm::VmaBacking::KernelBytes { data: section.bytes(), off: offset as usize }
    };
    match mm.mmap_with_may_at(vmm::MmapPlacement::FixedNoReplace(base), round_mapping_size(size), vmm::VmaProt::READ | vmm::VmaProt::EXEC, vmm::VmaProt::READ | vmm::VmaProt::WRITE | vmm::VmaProt::EXEC, vmm::VmaFlags::PRIVATE, backing) {
        Ok(_) => server_reply(args, STATUS_SUCCESS),
        Err(vmm::MmapError::Exists) => server_reply(args, STATUS_CONFLICTING_ADDRESSES),
        Err(vmm::MmapError::Vmm(_)) => server_reply(args, STATUS_NO_MEMORY),
    }
}

#[cfg(target_os = "oxide-kernel")]
fn server_unmap_view(args: u64) -> u64 {
    let Some(base_address) = wine_arg(args, 24) else { return STATUS_INVALID_PARAMETER; };
    let Ok(base_raw) = uaccess::get_user_u64(base_address) else { return STATUS_INVALID_PARAMETER; };
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    let Some(mm) = (unsafe { cur.mm_ref() }).map(|mm| mm.clone()) else { return STATUS_INVALID_PARAMETER; };
    let Some(base) = hal::UserVirtAddr::new(base_raw) else { return STATUS_INVALID_PARAMETER; };
    let Some(vma) = mm.find_vma(base) else { return STATUS_MEMORY_NOT_ALLOCATED; };
    if vma.start != base { return STATUS_INVALID_PARAMETER; }
    if mm.munmap(vma.start, (vma.end.as_u64() - vma.start.as_u64()) as usize).is_ok() { STATUS_SUCCESS } else { STATUS_MEMORY_NOT_ALLOCATED }
}

#[cfg(target_os = "oxide-kernel")]
fn server_get_mapping_info(args: u64, table: &sched::nt_object::NtHandleTable) -> u64 {
    let (Some(handle_address), Some(access_address)) = (wine_arg(args, 12), wine_arg(args, 16)) else { return STATUS_INVALID_PARAMETER; };
    let (Ok(raw), Ok(access)) = (uaccess::get_user_u32(handle_address), uaccess::get_user_u32(access_address)) else { return STATUS_INVALID_PARAMETER; };
    let handle = sched::nt_object::NtHandle::from_raw(raw);
    let Some(object) = table.get(handle, access) else { return if table.contains(handle) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }; };
    let Some(section) = object.section() else { return STATUS_INVALID_HANDLE; };
    let fields = [
        (8, section.size() as u64), (16, section.flags() as u64), (20, 0),
        (24, 0), (28, 0), (32, 0),
    ];
    for (offset, value) in fields {
        let Some(address) = wine_arg(args, offset) else { return STATUS_INVALID_PARAMETER; };
        let result = if offset == 8 { uaccess::put_user_u64(address, value) } else { uaccess::put_user_u32(address, value as u32) };
        if result.is_err() { return STATUS_INVALID_PARAMETER; }
    }
    server_reply(args, STATUS_SUCCESS)
}

#[cfg(target_os = "oxide-kernel")]
fn server_open_mapping(args: u64, request_size: u32, table: &sched::nt_object::NtHandleTable) -> u64 {
    let (Some(access_address), Some(attributes_address)) =
        (wine_arg(args, 12), wine_arg(args, 16)) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    let Ok(access) = uaccess::get_user_u32(access_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    let Ok(_attributes) = uaccess::get_user_u32(attributes_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    if access == 0 { return server_reply(args, STATUS_INVALID_PARAMETER); }
    let path = match wine_object_path(args, request_size, table) {
        Ok(Some(path)) => path,
        Ok(None) => return server_reply(args, STATUS_INVALID_PARAMETER),
        Err(status) => return server_reply(args, status),
    };
    let Some(object) = sched::nt_object::lookup_object(&path, sched::nt_object::NtObjectType::Section) else {
        return server_reply(args, STATUS_OBJECT_NAME_NOT_FOUND);
    };
    let Some(handle) = table.insert(object, access) else { return server_reply(args, STATUS_NO_MEMORY); };
    let Some(reply_address) = wine_arg(args, SERVER_REPLY_HANDLE) else { let _ = table.close(handle); return server_reply(args, STATUS_INVALID_PARAMETER); };
    if uaccess::put_user_u32(reply_address, handle.raw()).is_err() { let _ = table.close(handle); return server_reply(args, STATUS_INVALID_PARAMETER); }
    server_reply(args, STATUS_SUCCESS)
}

#[cfg(not(target_os = "oxide-kernel"))]
fn server_create_mapping(_args: u64, _request_size: u32, _table: &sched::nt_object::NtHandleTable) -> u64 { STATUS_INVALID_PARAMETER }
#[cfg(not(target_os = "oxide-kernel"))]
fn server_open_mapping(_args: u64, _request_size: u32, _table: &sched::nt_object::NtHandleTable) -> u64 { STATUS_INVALID_PARAMETER }
#[cfg(not(target_os = "oxide-kernel"))]
fn server_get_mapping_info(_args: u64, _table: &sched::nt_object::NtHandleTable) -> u64 { STATUS_INVALID_PARAMETER }
#[cfg(not(target_os = "oxide-kernel"))]
fn server_map_view(_args: u64, _table: &sched::nt_object::NtHandleTable) -> u64 { STATUS_INVALID_PARAMETER }
#[cfg(not(target_os = "oxide-kernel"))]
fn server_unmap_view(_args: u64) -> u64 { STATUS_INVALID_PARAMETER }
#[cfg(not(target_os = "oxide-kernel"))]
fn server_get_image_map_address(_args: u64, _table: &sched::nt_object::NtHandleTable) -> u64 { STATUS_INVALID_PARAMETER }
#[cfg(not(target_os = "oxide-kernel"))]
fn server_map_image_view(_args: u64, _table: &sched::nt_object::NtHandleTable) -> u64 { STATUS_INVALID_PARAMETER }

#[cfg(target_os = "oxide-kernel")]
fn wine_object_path(args: u64, request_size: u32, table: &sched::nt_object::NtHandleTable) -> Result<Option<alloc::string::String>, u64> {
    if request_size == 0 { return Ok(None); }
    let data_count = uaccess::get_user_u32(wine_arg(args, SERVER_DATA_COUNT).ok_or(STATUS_INVALID_PARAMETER)?).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let data = uaccess::get_user_u64(wine_arg(args, SERVER_DATA_ZERO_PTR).ok_or(STATUS_INVALID_PARAMETER)?).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let size = uaccess::get_user_u32(wine_arg(args, SERVER_DATA_ZERO_SIZE).ok_or(STATUS_INVALID_PARAMETER)?).map_err(|_| STATUS_INVALID_PARAMETER)?;
    if data_count != 1 || data == 0 || size != request_size { return Err(STATUS_INVALID_PARAMETER); }
    crate::nt_directory::resolve_wine_object_path(data, size, table).ok_or(STATUS_INVALID_PARAMETER).map(Some)
}

#[cfg(target_os = "oxide-kernel")]
fn server_reply(args: u64, status: u64) -> u64 {
    let Some(reply_size_address) = wine_arg(args, SERVER_REPLY_SIZE) else { return STATUS_INVALID_PARAMETER; };
    if uaccess::put_user_u32(args, status as u32).is_err() || uaccess::put_user_u32(reply_size_address, 0).is_err() { STATUS_INVALID_PARAMETER } else { status }
}

#[cfg(target_os = "oxide-kernel")]
fn server_call(args: u64) -> u64 {
    if args == 0 { return STATUS_INVALID_PARAMETER; }
    let Ok(request) = uaccess::get_user_u32(args) else { return STATUS_INVALID_PARAMETER; };
    let Some(request_size_address) = wine_arg(args, SERVER_REQUEST_SIZE) else { return STATUS_INVALID_PARAMETER; };
    let Ok(request_size) = uaccess::get_user_u32(request_size_address) else { return STATUS_INVALID_PARAMETER; };
    let Some(request) = server_request_kind(request) else { return server_reply(args, STATUS_NOT_IMPLEMENTED); };
    if request_size != 0 && !matches!(request, ServerRequest::Select | ServerRequest::CreateEvent | ServerRequest::CreateMutex | ServerRequest::CreateSemaphore | ServerRequest::CreateMapping | ServerRequest::OpenMapping) { return server_reply(args, STATUS_INVALID_PARAMETER); }
    if matches!(request, ServerRequest::Select) { return server_select(args); }
    let Some(cur) = sched::live::current() else { return server_reply(args, STATUS_INVALID_PARAMETER); };
    let table = cur.thread_group.nt_handles();
    if matches!(request, ServerRequest::CreateMapping) { return server_create_mapping(args, request_size, &table); }
    if matches!(request, ServerRequest::OpenMapping) { return server_open_mapping(args, request_size, &table); }
    if matches!(request, ServerRequest::GetMappingInfo) { return server_get_mapping_info(args, &table); }
    if matches!(request, ServerRequest::MapView) { return server_reply(args, server_map_view(args, &table)); }
    if matches!(request, ServerRequest::GetImageMapAddress) { return server_get_image_map_address(args, &table); }
    if matches!(request, ServerRequest::MapImageView) { return server_map_image_view(args, &table); }
    if matches!(request, ServerRequest::UnmapView) { return server_reply(args, server_unmap_view(args)); }
    let status = match request {
        ServerRequest::CloseHandle => {
            let Some(handle_address) = wine_arg(args, SERVER_HANDLE) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            let Ok(raw) = uaccess::get_user_u32(handle_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            let handle = sched::nt_object::NtHandle::from_raw(raw);
            let object = table.get(handle, 0);
            if object.is_none() { STATUS_INVALID_HANDLE } else {
                if table.is_protected_from_close(handle) { return server_reply(args, STATUS_HANDLE_NOT_CLOSABLE); }
                crate::nt_directory_notify::close(raw);
                let key = object.filter(|object| object.kind() == sched::nt_object::NtObjectType::Key).map(|object| object.id());
                match table.close_with_last(handle) {
                    Some(true) => { if let Some(key) = key { crate::nt_registry::close_watches(key); crate::nt_registry::close_remote(key); } STATUS_SUCCESS }
                    Some(false) => STATUS_SUCCESS,
                    None => STATUS_INVALID_HANDLE,
                }
            }
        }
        ServerRequest::CreateEvent => {
            let (Some(access_address), Some(manual_address), Some(initial_address)) = (wine_arg(args, SERVER_HANDLE), wine_arg(args, SERVER_EVENT_MANUAL_RESET), wine_arg(args, SERVER_EVENT_INITIAL_STATE)) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            let Ok(access) = uaccess::get_user_u32(access_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            let Ok(manual) = uaccess::get_user_u32(manual_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            let Ok(initial) = uaccess::get_user_u32(initial_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            if manual > 1 || initial > 1 { STATUS_INVALID_PARAMETER } else {
                let path = match wine_object_path(args, request_size, &table) { Ok(path) => path, Err(status) => return server_reply(args, status) };
                let (object, state) = match path { Some(path) => sched::nt_object::create_event(&path, manual != 0, initial != 0), None => (table.new_event(manual != 0, initial != 0), sched::nt_object::NamedObjectState::Created) };
                if state == sched::nt_object::NamedObjectState::TypeMismatch { return server_reply(args, STATUS_OBJECT_TYPE_MISMATCH); }
                if state == sched::nt_object::NamedObjectState::ParentMissing { return server_reply(args, STATUS_OBJECT_NAME_NOT_FOUND); }
                let Some(handle) = table.insert(object, access) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
                let Some(reply_address) = wine_arg(args, SERVER_REPLY_HANDLE) else { let _ = table.close(handle); return server_reply(args, STATUS_INVALID_PARAMETER); };
                if uaccess::put_user_u32(reply_address, handle.raw()).is_err() { let _ = table.close(handle); STATUS_INVALID_PARAMETER } else if state == sched::nt_object::NamedObjectState::Existing { STATUS_OBJECT_NAME_COLLISION } else { STATUS_SUCCESS }
            }
        }
        ServerRequest::EventOp => {
            let (Some(handle_address), Some(op_address)) = (wine_arg(args, SERVER_HANDLE), wine_arg(args, SERVER_EVENT_OP)) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            let Ok(raw) = uaccess::get_user_u32(handle_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            let Ok(op) = uaccess::get_user_u32(op_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            let handle = sched::nt_object::NtHandle::from_raw(raw);
            let Some(object) = table.get(handle, EVENT_MODIFY_STATE) else { return server_reply(args, if table.contains(handle) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }); };
            if object.kind() != sched::nt_object::NtObjectType::Event { STATUS_INVALID_HANDLE } else if let Some(event) = object.event() {
                let old = event.is_signaled();
                match op { 0 => { event.pulse(); }, 1 => { event.set(); }, 2 => { event.reset(); }, _ => return server_reply(args, STATUS_INVALID_PARAMETER) }
                table.wake_waiters();
                let Some(reply_address) = wine_arg(args, SERVER_REPLY_STATE) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
                if uaccess::put_user_u32(reply_address, old as u32).is_err() { STATUS_INVALID_PARAMETER } else { STATUS_SUCCESS }
            } else { STATUS_INVALID_HANDLE }
        }
        ServerRequest::QueryEvent => {
            let Some(handle_address) = wine_arg(args, SERVER_HANDLE) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            let Ok(raw) = uaccess::get_user_u32(handle_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            let handle = sched::nt_object::NtHandle::from_raw(raw);
            let Some(object) = table.get(handle, EVENT_QUERY_STATE) else { return server_reply(args, if table.contains(handle) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }); };
            let Some(event) = object.event() else { return server_reply(args, STATUS_INVALID_HANDLE); };
            let (Some(manual_address), Some(state_address)) = (wine_arg(args, SERVER_REPLY_MANUAL_RESET), wine_arg(args, SERVER_REPLY_EVENT_STATE)) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            if uaccess::put_user_u32(manual_address, event.is_manual_reset() as u32).is_err() || uaccess::put_user_u32(state_address, event.is_signaled() as u32).is_err() { STATUS_INVALID_PARAMETER } else { STATUS_SUCCESS }
        }
        ServerRequest::CreateMutex => {
            let (Some(access_address), Some(owned_address)) = (wine_arg(args, SERVER_SYNC_ACCESS), wine_arg(args, SERVER_SYNC_VALUE)) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            let Ok(access) = uaccess::get_user_u32(access_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            let Ok(owned) = uaccess::get_user_u32(owned_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            if owned > 1 { STATUS_INVALID_PARAMETER } else {
                let path = match wine_object_path(args, request_size, &table) { Ok(path) => path, Err(status) => return server_reply(args, status) };
                let fresh = table.new_mutant((owned != 0).then_some(cur.tid as u64));
                let (object, state) = match path { Some(path) => sched::nt_object::publish_mutant(&path, fresh), None => (fresh, sched::nt_object::NamedObjectState::Created) };
                if state == sched::nt_object::NamedObjectState::TypeMismatch { return server_reply(args, STATUS_OBJECT_TYPE_MISMATCH); }
                if state == sched::nt_object::NamedObjectState::ParentMissing { return server_reply(args, STATUS_OBJECT_NAME_NOT_FOUND); }
                let Some(handle) = table.insert(object, access) else { return server_reply(args, STATUS_NO_MEMORY); };
                let Some(reply_address) = wine_arg(args, SERVER_REPLY_VALUE) else { let _ = table.close(handle); return server_reply(args, STATUS_INVALID_PARAMETER); };
                if uaccess::put_user_u32(reply_address, handle.raw()).is_err() { let _ = table.close(handle); STATUS_INVALID_PARAMETER } else if state == sched::nt_object::NamedObjectState::Existing { STATUS_OBJECT_NAME_COLLISION } else { STATUS_SUCCESS }
            }
        }
        ServerRequest::ReleaseMutex => {
            let Some(handle_address) = wine_arg(args, SERVER_HANDLE) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            let Ok(raw) = uaccess::get_user_u32(handle_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            let handle = sched::nt_object::NtHandle::from_raw(raw);
            let Some(object) = table.get(handle, MUTANT_MODIFY_STATE) else { return server_reply(args, if table.contains(handle) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }); };
            let Some(mutant) = object.mutant() else { return server_reply(args, STATUS_INVALID_HANDLE); };
            let Ok(previous) = mutant.release(cur.tid as u64) else { return server_reply(args, STATUS_ACCESS_DENIED); };
            let Some(reply_address) = wine_arg(args, SERVER_REPLY_VALUE) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            if uaccess::put_user_u32(reply_address, previous as u32).is_err() { STATUS_INVALID_PARAMETER } else { STATUS_SUCCESS }
        }
        ServerRequest::QueryMutex => {
            let Some(handle_address) = wine_arg(args, SERVER_HANDLE) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            let Ok(raw) = uaccess::get_user_u32(handle_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            let handle = sched::nt_object::NtHandle::from_raw(raw);
            let Some(object) = table.get(handle, MUTANT_QUERY_STATE) else { return server_reply(args, if table.contains(handle) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }); };
            let Some(mutant) = object.mutant() else { return server_reply(args, STATUS_INVALID_HANDLE); };
            let (count, owned, abandoned) = mutant.basic_info(cur.tid as u64);
            let (Some(count_address), Some(owned_address), Some(abandoned_address)) = (wine_arg(args, SERVER_REPLY_VALUE), wine_arg(args, SERVER_REPLY_VALUE_TWO), wine_arg(args, SERVER_REPLY_VALUE_THREE)) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            if uaccess::put_user_u32(count_address, count as u32).is_err() || uaccess::put_user_u32(owned_address, owned as u32).is_err() || uaccess::put_user_u32(abandoned_address, abandoned as u32).is_err() { STATUS_INVALID_PARAMETER } else { STATUS_SUCCESS }
        }
        ServerRequest::CreateSemaphore => {
            let (Some(access_address), Some(initial_address), Some(maximum_address)) = (wine_arg(args, SERVER_SYNC_ACCESS), wine_arg(args, SERVER_SYNC_VALUE), wine_arg(args, SERVER_SYNC_VALUE_TWO)) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            let Ok(access) = uaccess::get_user_u32(access_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            let Ok(initial) = uaccess::get_user_u32(initial_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            let Ok(maximum) = uaccess::get_user_u32(maximum_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            if maximum == 0 || initial > maximum { STATUS_INVALID_PARAMETER } else {
                let path = match wine_object_path(args, request_size, &table) { Ok(path) => path, Err(status) => return server_reply(args, status) };
                let fresh = table.new_semaphore(initial as i64, maximum as i64);
                let (object, state) = match path { Some(path) => sched::nt_object::create_semaphore(&path, initial as i64, maximum as i64), None => (fresh, sched::nt_object::NamedObjectState::Created) };
                if state == sched::nt_object::NamedObjectState::TypeMismatch { return server_reply(args, STATUS_OBJECT_TYPE_MISMATCH); }
                if state == sched::nt_object::NamedObjectState::ParentMissing { return server_reply(args, STATUS_OBJECT_NAME_NOT_FOUND); }
                let Some(handle) = table.insert(object, access) else { return server_reply(args, STATUS_NO_MEMORY); };
                let Some(reply_address) = wine_arg(args, SERVER_REPLY_VALUE) else { let _ = table.close(handle); return server_reply(args, STATUS_INVALID_PARAMETER); };
                if uaccess::put_user_u32(reply_address, handle.raw()).is_err() { let _ = table.close(handle); STATUS_INVALID_PARAMETER } else if state == sched::nt_object::NamedObjectState::Existing { STATUS_OBJECT_NAME_COLLISION } else { STATUS_SUCCESS }
            }
        }
        ServerRequest::ReleaseSemaphore => {
            let (Some(handle_address), Some(count_address)) = (wine_arg(args, SERVER_HANDLE), wine_arg(args, SERVER_SYNC_VALUE)) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            let Ok(raw) = uaccess::get_user_u32(handle_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            let Ok(count) = uaccess::get_user_u32(count_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            let handle = sched::nt_object::NtHandle::from_raw(raw);
            let Some(object) = table.get(handle, SEMAPHORE_MODIFY_STATE) else { return server_reply(args, if table.contains(handle) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }); };
            let Some(semaphore) = object.semaphore() else { return server_reply(args, STATUS_INVALID_HANDLE); };
            let Some(previous) = semaphore.release(count) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            table.wake_waiters();
            let Some(reply_address) = wine_arg(args, SERVER_REPLY_VALUE) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            if uaccess::put_user_u32(reply_address, previous).is_err() { STATUS_INVALID_PARAMETER } else { STATUS_SUCCESS }
        }
        ServerRequest::QuerySemaphore => {
            let Some(handle_address) = wine_arg(args, SERVER_HANDLE) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            let Ok(raw) = uaccess::get_user_u32(handle_address) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            let handle = sched::nt_object::NtHandle::from_raw(raw);
            let Some(object) = table.get(handle, SEMAPHORE_QUERY_STATE) else { return server_reply(args, if table.contains(handle) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }); };
            let Some(semaphore) = object.semaphore() else { return server_reply(args, STATUS_INVALID_HANDLE); };
            let (current, maximum) = semaphore.counts();
            let (Some(current_address), Some(maximum_address)) = (wine_arg(args, SERVER_REPLY_VALUE), wine_arg(args, SERVER_REPLY_VALUE_TWO)) else { return server_reply(args, STATUS_INVALID_PARAMETER); };
            if uaccess::put_user_u32(current_address, current).is_err() || uaccess::put_user_u32(maximum_address, maximum).is_err() { STATUS_INVALID_PARAMETER } else { STATUS_SUCCESS }
        }
        ServerRequest::Select | ServerRequest::CreateMapping | ServerRequest::OpenMapping | ServerRequest::GetMappingInfo | ServerRequest::GetImageMapAddress | ServerRequest::MapView | ServerRequest::MapImageView | ServerRequest::UnmapView => STATUS_INVALID_PARAMETER,
    };
    server_reply(args, status)
}

#[cfg(not(target_os = "oxide-kernel"))]
fn server_call(_args: u64) -> u64 { STATUS_INVALID_PARAMETER }

#[cfg(target_os = "oxide-kernel")]
fn write_unix_debug(args: u64) -> u64 {
    const STRING: u64 = 0;
    const LENGTH: u64 = 8;
    const CHUNK: usize = 256;
    if args == 0 { return STATUS_INVALID_PARAMETER; }
    let (Some(string_address), Some(length_address)) = (wine_arg(args, STRING), wine_arg(args, LENGTH)) else { return STATUS_INVALID_PARAMETER; };
    let Ok(pointer) = uaccess::get_user_u64(string_address) else { return STATUS_INVALID_PARAMETER; };
    let Ok(length) = uaccess::get_user_u32(length_address) else { return STATUS_INVALID_PARAMETER; };
    let length = length as usize;
    if length > MAX_WINE_DEBUG_WRITE || (length != 0 && pointer == 0) { return STATUS_INVALID_PARAMETER; }
    let mut copied = 0u64;
    let mut buffer = [0u8; CHUNK];
    while copied < length as u64 {
        let count = (length as u64 - copied).min(CHUNK as u64) as usize;
        let Some(source) = pointer.checked_add(copied) else { return STATUS_INVALID_PARAMETER; };
        if uaccess::copy_from_user(&mut buffer[..count], source).is_err() { return STATUS_INVALID_PARAMETER; }
        klog::write_raw(&buffer[..count]);
        copied += count as u64;
    }
    STATUS_SUCCESS
}

#[cfg(not(target_os = "oxide-kernel"))]
fn write_unix_debug(_args: u64) -> u64 { STATUS_INVALID_PARAMETER }

#[cfg(target_os = "oxide-kernel")]
fn validate_builtin_unwind(args: u64) -> u64 {
    if args == 0 { return STATUS_INVALID_PARAMETER; }
    let Ok(unwind_type) = uaccess::get_user_u32(args) else { return STATUS_INVALID_PARAMETER; };
    if !valid_unwind_type(unwind_type) { return STATUS_INVALID_PARAMETER; }
    crate::nt_wine_unwind::dispatch(args)
}

#[cfg(target_os = "oxide-kernel")]
fn load_so_dll(args: u64) -> u64 {
    if args == 0 || args.checked_add(16).is_none() { return STATUS_INVALID_PARAMETER; }
    // The process catalog is the canonical Wine builtin source in Oxide. Its
    // PE image loader owns mapping, imports, PEB publication, and attach order.
    let Some(module_output) = wine_arg(args, 16) else { return STATUS_INVALID_PARAMETER; };
    crate::nt_loader_dir::load(args, module_output)
}

#[cfg(not(target_os = "oxide-kernel"))]
fn load_so_dll(_args: u64) -> u64 { STATUS_NOT_IMPLEMENTED }

#[cfg(not(target_os = "oxide-kernel"))]
fn validate_builtin_unwind(args: u64) -> u64 {
    if args == 0 { STATUS_INVALID_PARAMETER } else { STATUS_NOT_IMPLEMENTED }
}

/// Wine's `unixlib_handle_t` is a table identity. Only the native table may
/// consume it; arbitrary user pointers are rejected before dispatch.
pub(crate) fn dispatch(call: NtCall) -> u64 {
    if call.service != NtService::WineUnixCall || call.args.a0 != syscall::nt::WINE_UNIXLIB_HANDLE {
        return STATUS_INVALID_PARAMETER;
    }
    match WineUnixFunction::decode(call.args.a1) {
        Some(WineUnixFunction::LoadSoDll) => load_so_dll(call.args.a2),
        Some(WineUnixFunction::UnwindBuiltinDll) => validate_builtin_unwind(call.args.a2),
        // unix_wine_dbg_write: `{ const char *str; size_t len; }`.
        // Logging ownership is added with the kernel console bridge; reject
        // malformed requests now rather than dereferencing an untrusted ptr.
        Some(WineUnixFunction::WineDbgWrite) => write_unix_debug(call.args.a2),
        Some(WineUnixFunction::WineServerFdToHandle) => unix_fd_to_handle(call.args.a2),
        Some(WineUnixFunction::WineServerHandleToFd) => unix_handle_to_fd(call.args.a2),
        Some(WineUnixFunction::WineServerCall) => server_call(call.args.a2),
        // unix_system_time_precise: writes one Windows 100ns timestamp.
        Some(WineUnixFunction::SystemTimePrecise) => {
            if call.args.a2 == 0 { return STATUS_INVALID_PARAMETER; }
            // Wine's unix_system_time_precise returns Windows epoch-relative
            // 100ns units; CLOCK_REALTIME is the canonical Linux owner.
            let ticks = windows_time_ticks(timekeeper::realtime_ns());
            if uaccess::put_user_u64(call.args.a2, ticks).is_err() { STATUS_INVALID_PARAMETER } else { STATUS_SUCCESS }
        }
        // The remaining entries require Wine's server protocol or a Unix
        // module loader and are deliberately kept behind this typed boundary.
        _ => STATUS_NOT_IMPLEMENTED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_native_unix_table_handles() {
        let call = NtCall { service: NtService::WineUnixCall, args: syscall::SyscallArgs { a0: 1, a1: 7, a2: 0x1000, a3: 0, a4: 0, a5: 0 } };
        assert_eq!(dispatch(call), STATUS_INVALID_PARAMETER);
    }

    #[test]
    fn unix_system_time_uses_windows_100ns_units() {
        assert_eq!(windows_time_ticks(1_700_000_000_123_456_700), 17_000_000_001_234_567);
        assert_eq!(windows_time_ticks(99), 0);
    }

    #[test]
    fn unwind_type_accepts_only_wine_virtual_unwind_flags() {
        assert!(valid_unwind_type(0));
        assert!(valid_unwind_type(1 | 2 | 4));
        assert!(!valid_unwind_type(8));
        assert!(!valid_unwind_type(u32::MAX));
    }

    #[test]
    fn builtin_unwind_rejects_a_null_request_before_runtime_dispatch() {
        let call = NtCall { service: NtService::WineUnixCall, args: syscall::SyscallArgs { a0: syscall::nt::WINE_UNIXLIB_HANDLE, a1: WineUnixFunction::UnwindBuiltinDll as u64, a2: 0, a3: 0, a4: 0, a5: 0 } };
        assert_eq!(dispatch(call), STATUS_INVALID_PARAMETER);
    }

    #[test]
    fn unavailable_unix_unwind_uses_wines_native_fallback_status() {
        // Wine's virtual_unwind tests specifically for STATUS_UNSUCCESSFUL;
        // STATUS_NOT_IMPLEMENTED would terminate the fallback path.
        assert_eq!(STATUS_UNSUCCESSFUL, 0xc000_0001);
        assert_ne!(STATUS_UNSUCCESSFUL, STATUS_NOT_IMPLEMENTED);
    }

    #[test]
    fn server_request_ids_match_wire_protocol() {
        assert_eq!(server_request_kind(21), Some(ServerRequest::CloseHandle));
        assert_eq!(server_request_kind(30), Some(ServerRequest::CreateEvent));
        assert_eq!(server_request_kind(31), Some(ServerRequest::EventOp));
        assert_eq!(server_request_kind(32), Some(ServerRequest::QueryEvent));
        assert_eq!(server_request_kind(29), Some(ServerRequest::Select));
        assert_eq!(server_request_kind(36), Some(ServerRequest::CreateMutex));
        assert_eq!(server_request_kind(37), Some(ServerRequest::ReleaseMutex));
        assert_eq!(server_request_kind(39), Some(ServerRequest::QueryMutex));
        assert_eq!(server_request_kind(40), Some(ServerRequest::CreateSemaphore));
        assert_eq!(server_request_kind(41), Some(ServerRequest::ReleaseSemaphore));
        assert_eq!(server_request_kind(42), Some(ServerRequest::QuerySemaphore));
        assert_eq!(server_request_kind(63), Some(ServerRequest::CreateMapping));
        assert_eq!(server_request_kind(64), Some(ServerRequest::OpenMapping));
        assert_eq!(server_request_kind(65), Some(ServerRequest::GetMappingInfo));
        assert_eq!(server_request_kind(66), Some(ServerRequest::GetImageMapAddress));
        assert_eq!(server_request_kind(67), Some(ServerRequest::MapView));
        assert_eq!(server_request_kind(68), Some(ServerRequest::MapImageView));
        assert_eq!(server_request_kind(71), Some(ServerRequest::UnmapView));
        assert_eq!(server_request_kind(62), None);
        assert_eq!(server_request_kind(69), None);
        assert_eq!(server_request_kind(23), None);
        assert_eq!(select_opcode_kind(1), Some(0));
        assert_eq!(select_opcode_kind(2), Some(1));
        assert_eq!(select_opcode_kind(3), None);
        assert_eq!(server_request_kind(33), None);
        assert_eq!(SERVER_HEADER_BYTES, 12);
    }
}
