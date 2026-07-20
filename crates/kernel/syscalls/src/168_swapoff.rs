//! Linux `swapoff(2)` ABI shim; live migration is owned by `pmm::user_as`.
#![cfg(target_os = "oxide-kernel")]

use syscall::{errno::Errno, SyscallArgs};

/// `swapoff(special)` — slot 168. Resolves a canonical block disk and drains
/// all of its live swap PTEs before removing the area.
/// # C: O(path + all live user page tables + swapped pages * page I/O)
pub fn sys_swapoff(args: &SyscallArgs) -> i64 {
    let current = match sched::live::current() {
        Some(current) => current,
        None => return errno(Errno::Esrch),
    };
    if !current.has_cap(sched::cap::SYS_ADMIN) { return errno(Errno::Eperm); }
    let path = match crate::namei_common::read_user_path(args.a0) {
        Ok(path) => path,
        Err(result) => return result,
    };
    let node = match crate::pathresolve::resolve_path_raw(&path, true) {
        Ok(node) => node,
        Err(error) => return crate::namei_common::errno_from_vfs(error),
    };
    let name = match node.inode.file_type() {
        vfs::FileType::BlockDev => match block::registry::by_dev(node.inode.rdev()) {
            Some(disk) => disk.name.clone(),
            None => return errno(Errno::Enodev),
        },
        vfs::FileType::Regular => match ext4::rootfs::swapfile_name(&node.inode) {
            Some(name) => name,
            None => return errno(Errno::Einval),
        },
        _ => return errno(Errno::Einval),
    };
    let kind = match pmm::swap::kind_for_name(&name) {
        Some(kind) => kind,
        None => return errno(Errno::Einval),
    };
    match pmm::user_as::drain_swap_area(kind) {
        Ok(()) => 0,
        Err(error) => drain_errno(error),
    }
}

/// # C: O(1)
fn errno(error: Errno) -> i64 { -(error.as_i32() as i64) }

/// Preserve Linux-visible resource, I/O, and invalid-state failure classes.
/// # C: O(1)
fn drain_errno(error: vmm::Error) -> i64 {
    let code = match error {
        vmm::Error::NoMem => Errno::Enomem,
        vmm::Error::Io => Errno::Eio,
        vmm::Error::Inval => Errno::Ebusy,
        _ => Errno::Eio,
    };
    errno(code)
}
