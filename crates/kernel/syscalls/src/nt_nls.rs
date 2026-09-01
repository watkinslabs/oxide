//! Native NLS section lookup over the guest's Wine-compatible data files.

#![cfg(target_os = "oxide-kernel")]

use alloc::format;
use syscall::nt::{NtCall, NtThreadCall};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xc000_0034;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
const NLS_SORTKEYS: u32 = 9;
const NLS_CASEMAP: u32 = 10;
const NLS_CODEPAGE: u32 = 11;
const NLS_NORMALIZE: u32 = 12;

/// Resolve and map one Wine NLS data file into the current NT process.
///
/// The file remains owned by the VMA's `InodeFileBacking`, so the returned
/// pointer is valid after this adapter returns and shares the normal page
/// cache/fault path with every other file mapping.
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != syscall::nt::NtService::NtGetNlsSectionPtr { return None; }
    Some(get_section(call))
}

fn get_section(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let Ok(NtThreadCall::GetNlsSection { section, id, unknown, pointer, size }) = syscall::nt::decode_thread(call) else {
        return STATUS_INVALID_PARAMETER;
    };
    if unknown != 0 { return STATUS_INVALID_PARAMETER; }
    let name = match section {
        NLS_SORTKEYS if id == 0 => "sortdefault",
        NLS_CASEMAP if id == 0 => "l_intl",
        NLS_CODEPAGE => return map_named(cur, format!("c_{id:03}"), pointer.as_u64(), size.as_u64()),
        NLS_NORMALIZE => match id {
            1 => "normnfc", 2 => "normnfd", 3 => "normnfkc", 4 => "normnfkd", 13 => "normidna",
            _ => return STATUS_OBJECT_NAME_NOT_FOUND,
        },
        _ => return STATUS_OBJECT_NAME_NOT_FOUND,
    };
    map_named(cur, name.into(), pointer.as_u64(), size.as_u64())
}

fn map_named(cur: &sched::Task, name: alloc::string::String, pointer: u64, size: u64) -> u64 {
    if pointer == 0 || size == 0 { return STATUS_INVALID_PARAMETER; }
    let path = format!("/usr/share/wine/nls/{name}.nls");
    let vp = match crate::pathresolve::resolve_at_path(crate::pathresolve::AT_FDCWD, &path, vfs::LookupFlags::default()) {
        Ok(vp) => vp,
        Err(_) => return STATUS_OBJECT_NAME_NOT_FOUND,
    };
    let file_size = vp.inode.size();
    if file_size == 0 { return STATUS_OBJECT_NAME_NOT_FOUND; }
    let page = hal::PAGE_SIZE_BYTES as u64;
    let mapped = match file_size.checked_add(page - 1).map(|v| v & !(page - 1)) {
        Some(mapped) if mapped != 0 => mapped,
        _ => return STATUS_NO_MEMORY,
    };
    let Some(mm) = (unsafe { cur.mm_ref() }).map(|mm| mm.clone()) else { return STATUS_INVALID_PARAMETER; };
    let backing = crate::mmap_file::InodeFileBacking::new_named(vp.inode, path.into_bytes());
    let address = match mm.mmap(None, mapped as usize, vmm::VmaProt::READ, vmm::VmaFlags::PRIVATE,
        vmm::VmaBacking::File { backing, off: 0 }, false) {
        Ok(address) => address.as_u64(),
        Err(_) => return STATUS_NO_MEMORY,
    };
    if uaccess::put_user_u64(pointer, address).is_err() || uaccess::put_user_u64(size, file_size).is_err() {
        let _ = mm.munmap(hal::UserVirtAddr::new(address).unwrap(), mapped as usize);
        return STATUS_INVALID_PARAMETER;
    }
    STATUS_SUCCESS
}
