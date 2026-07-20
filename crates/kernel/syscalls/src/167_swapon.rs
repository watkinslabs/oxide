//! Linux `swapon(2)` ABI shim; canonical state lives in `pmm::swap`.
#![cfg(target_os = "oxide-kernel")]

use syscall::{errno::Errno, SyscallArgs};

#[path = "167_swapon/uapi.rs"]
mod uapi;
use uapi::*;

/// `swapon(special, swap_flags)` — slot 167. Resolves a real block node,
/// validates Linux priority flags, and activates its canonical PMM swap area.
/// # C: O(path + device pages + header I/O)
pub fn sys_swapon(args: &SyscallArgs) -> i64 {
    #[cfg(any(feature = "debug-boot", feature = "debug-swap"))]
    {
        klog::write_raw(b"[SWAPON] request flags=");
        klog::write_hex_u64(args.a1);
        klog::write_raw(b"\n");
    }
    let current = match sched::live::current() {
        Some(current) => current,
        None => return errno(Errno::Esrch),
    };
    if !current.has_cap(sched::cap::SYS_ADMIN) { return errno(Errno::Eperm); }
    if args.a1 & !SUPPORTED_SWAPON_FLAGS != 0 { return errno(Errno::Einval); }
    let path = match crate::namei_common::read_user_path(args.a0) {
        Ok(path) => path,
        Err(result) => return result,
    };
    let node = match crate::pathresolve::resolve_path_raw(&path, true) {
        Ok(node) => node,
        Err(error) => return crate::namei_common::errno_from_vfs(error),
    };
    let priority = (args.a1 & SWAP_FLAG_PREFER != 0)
        .then_some((args.a1 & SWAP_FLAG_PRIO_MASK) as i32);
    let discard = pmm::swap::SwapDiscard::from_swapon(
        args.a1 & SWAP_FLAG_DISCARD != 0,
        args.a1 & SWAP_FLAG_DISCARD_ONCE != 0,
        args.a1 & SWAP_FLAG_DISCARD_PAGES != 0,
    );
    let result = match node.inode.file_type() {
        vfs::FileType::BlockDev => {
            let disk = match block::registry::by_dev(node.inode.rdev()) {
                Some(disk) => disk,
                None => return errno(Errno::Enodev),
            };
            #[cfg(any(feature = "debug-boot", feature = "debug-swap"))]
            { klog::write_raw(b"[SWAPON] activate "); klog::write_raw(disk.name.as_bytes()); klog::write_raw(b"\n"); }
            pmm::swap::activate_registered_with_options(&disk.name, priority, discard)
        }
        vfs::FileType::Regular => {
            let backing = match ext4::rootfs::swapfile_backing(&node.inode) {
                Ok(backing) => backing,
                Err(error) => return crate::namei_common::errno_from_vfs(error),
            };
            #[cfg(any(feature = "debug-boot", feature = "debug-swap"))]
            { klog::write_raw(b"[SWAPON] activate "); klog::write_raw(backing.name.as_bytes()); klog::write_raw(b"\n"); }
            pmm::swap::activate_file_with_options(backing.name, path, backing.device, priority, discard)
        }
        _ => return errno(Errno::Einval),
    };
    #[cfg(any(feature = "debug-boot", feature = "debug-swap"))]
    {
        klog::write_raw(b"[SWAPON] activate returned\n");
    }
    match result {
        Ok(_) => 0,
        Err(error) => swap_errno(error),
    }
}

/// # C: O(1)
fn errno(error: Errno) -> i64 { -(error.as_i32() as i64) }

/// Canonical PMM-swap errors translated at the Linux ABI boundary.
/// # C: O(1)
fn swap_errno(error: pmm::swap::SwapError) -> i64 {
    let code = match error {
        pmm::swap::SwapError::Busy => Errno::Ebusy,
        pmm::swap::SwapError::Inval => Errno::Einval,
        pmm::swap::SwapError::Io => Errno::Eio,
        pmm::swap::SwapError::NoMem => Errno::Enomem,
        pmm::swap::SwapError::NoSpace => Errno::Enospc,
        pmm::swap::SwapError::NoSuchArea => Errno::Enodev,
    };
    errno(code)
}
