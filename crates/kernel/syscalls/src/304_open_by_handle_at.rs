// open_by_handle_at(2) per `15§5` / `16` — the reverse of name_to_handle_at.
// Reopens a file from the exportable handle that 303 emitted (an 8-byte inode
// FID, handle_type = 1). Linux resolves it via exportfs `fh_to_dentry`: the
// `mount_fd` identifies the filesystem (its superblock), the FID supplies the
// inode number, and the inode is reconstructed/looked up on that superblock.
//
// FID -> inode mechanism here: `mount_fd` -> open File -> `f_inode.i_sb()`
// (the superblock the fd's filesystem) -> `sb.ilookup(ino)`. A resident inode
// (still cached on the sb) resolves; an inode that is gone -> ESTALE, exactly
// Linux's `fh_to_dentry` staleness contract. The reopened File is built over a
// disconnected dentry alias (`d_obtain_alias`, Linux exportfs), honoring the
// open flags, and installed via the rlimit-aware fd allocator.
//
// CAP_DAC_READ_SEARCH is mandatory (Linux `do_handle_open` gate): the handle
// bypasses path-based permission, so only a caller that may search any path
// may resolve one.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::{File, OpenFlags};

use crate::userbuf::validate_user_buf;

// struct file_handle { __u32 handle_bytes; int handle_type; unsigned char f_handle[]; }
// 303 writes an 8-byte inode FID at offset 8 with handle_type = 1.
const FID_LEN: u32 = 8;
const HANDLE_TYPE_INO: i32 = 1;
const HANDLE_HDR: u64 = 8; // handle_bytes(4) + handle_type(4)

/// `sys_open_by_handle_at(mount_fd, file_handle, flags)` — slot 304.
/// Parses the `file_handle` (must be the 8-byte inode FID, `handle_type == 1`
/// that 303 emits), resolves it against `mount_fd`'s superblock by inode
/// number, builds a File honoring `flags` (O_RDONLY/O_WRONLY/O_RDWR/O_PATH/…),
/// and installs an fd under the RLIMIT_NOFILE soft cap.
/// Errors: EPERM (no CAP_DAC_READ_SEARCH), EBADF (bad `mount_fd`), EINVAL
/// (malformed handle), ESTALE (inode no longer resident / gone).
/// # C: O(log N_ino)
pub fn sys_open_by_handle_at(args: &SyscallArgs) -> i64 {
    let mount_fd = args.a0 as i32;
    let handle_ptr = args.a1;
    let flags = args.a2 as u32;

    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // CAP_DAC_READ_SEARCH gate (Linux `do_handle_open` -> `may_decode_fh`):
    // the handle sidesteps path-walk permission, so the caller must hold the
    // search-anything capability.
    if !cur.has_cap(sched::cap::DAC_READ_SEARCH) {
        return -(Errno::Eperm.as_i32() as i64);
    }

    // Read + validate the file_handle header (handle_bytes, handle_type).
    if let Err(rv) = validate_user_buf(handle_ptr, HANDLE_HDR, 1) { return rv; }
    // SAFETY: handle_ptr validated readable for the 8-byte header in the caller's AS by validate_user_buf; aligned reads of handle_bytes(u32) then handle_type(i32).
    let (bytes, htype) = unsafe {
        (core::ptr::read_volatile(handle_ptr as *const u32),
         core::ptr::read_volatile((handle_ptr + 4) as *const i32))
    };
    // Only the 8-byte inode FID with handle_type == 1 (what 303 emits) is
    // decodable; anything else is a foreign/malformed handle -> EINVAL.
    if bytes != FID_LEN || htype != HANDLE_TYPE_INO {
        return -(Errno::Einval.as_i32() as i64);
    }
    if let Err(rv) = validate_user_buf(handle_ptr + HANDLE_HDR, FID_LEN as u64, 1) { return rv; }
    // SAFETY: f_handle region validated readable for FID_LEN bytes; byte-wise volatile reads of the 8-byte little-endian inode FID.
    let mut fid = [0u8; FID_LEN as usize];
    for (i, b) in fid.iter_mut().enumerate() {
        *b = unsafe { core::ptr::read_volatile((handle_ptr + HANDLE_HDR + i as u64) as *const u8) };
    }
    let ino = u64::from_le_bytes(fid);

    // mount_fd identifies the filesystem: resolve its superblock from the open
    // file's inode, then the encoded inode number on that sb.
    // SAFETY: fd_table slot single-mutator per `13§5`; running task on this CPU; clone Arc.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let mnt_file = match fdt.get(mount_fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let sb = match mnt_file.f_inode().i_sb() {
        Some(s) => s, None => return -(Errno::Estale.as_i32() as i64),
    };
    // exportfs `fh_to_dentry`: a resident inode on this sb resolves; a gone /
    // evicted inode -> ESTALE (the on-disk inode cannot be re-read by ino in v1
    // — no `s_export_op` backend hook — so non-resident == stale).
    let inode = match sb.ilookup(ino) {
        Some(i) => i, None => return -(Errno::Estale.as_i32() as i64),
    };

    // DAC + EROFS enforcement against the requested access mode (Linux
    // `do_handle_open` -> `vfs_open` -> `may_open`), through the mount the
    // handle was decoded on.
    let mnt_id = mnt_file.mnt_id();
    if let Some(rv) = crate::open_common::enforce_open_perm(&inode, mnt_id, flags, false) {
        return rv;
    }
    // Disconnected dentry alias (Linux exportfs `d_obtain_alias`): reuses a live
    // alias if the inode already has one, else allocates an anonymous one.
    let dentry = vfs::dcache::d_obtain_alias(inode.clone());
    let oflags = OpenFlags::from_bits_truncate(flags) - OpenFlags::O_CLOEXEC;
    let file_cred = match crate::pathresolve::file_cred_for(&cur) {
        Some(cred) => cred, None => return -(Errno::Esrch.as_i32() as i64),
    };
    let file = File::new_at(inode, dentry, oflags, mnt_id, file_cred);
    if let Err(e) = file.open_hook() { return -(e as i64); }
    match fdt.alloc_limit(file, cur.nofile_soft()) {
        Ok(fd) => {
            if (flags & OpenFlags::O_CLOEXEC.bits()) != 0 {
                if let Err(e) = fdt.set_cloexec(fd, true) { return -(e as i64); }
            }
            fd as i64
        }
        Err(e) => -(e as i64),
    }
}
