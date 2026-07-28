// name_to_handle_at(2) per `15§5` / `16`. Linux exportable file handles:
// encode inode identity so userspace can test two paths for same-inode-ness
// without holding fds open. systemd uses it in mountpoint detection and chroot
// checks, comparing the FID plus the returned mount id.
//
// The handle we emit is the 8-byte inode number (FILEID-style); the returned
// mount id is the resolved `struct path` mount id. Same inode + same mount id
// means userspace sees the same mounted object. open_by_handle_at (the reverse)
// is 304_open_by_handle_at.rs, decoding this same FID.
//
// ABI constants, flag masks and the capacity protocol live in
// `crate::handle_policy` (hosted-tested); this file is the shim (docs/53).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::handle_policy::{FID_LEN, FILEID_IS_CONNECTABLE, FILEID_IS_DIR, HANDLE_HDR,
    HANDLE_TYPE_INO, handle_capacity_check, name_to_handle_flags_check};
use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

#[cfg(feature = "debug-mount")]
fn log_runtime_handle(op: &'static str, dirfd: i32, path_ptr: u64, rv: i64) {
    if let Ok(path) = crate::namei_common::read_user_path(path_ptr) {
        if path.starts_with("/run/systemd") || path.contains("systemd/journal") {
            let mut tag = alloc::string::String::from(path.as_str());
            tag.push_str(" dirfd=");
            tag.push_str(&alloc::format!("{}", dirfd));
            crate::mount_common::mnt_log(op, &tag, rv);
        }
    }
}

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Write `handle_bytes` back and report EOVERFLOW — Linux's grow-and-retry
/// protocol (`do_sys_name_to_handle`: on `FILEID_INVALID` it stores the size
/// the encoder needs, copies out only the fixed header, and returns EOVERFLOW).
/// # C: O(1)
fn overflow(handle_ptr: u64, needed: u32) -> i64 {
    if let Err(rv) = validate_user_buf_writable(handle_ptr, 4, 1) { return rv; }
    // SAFETY: handle_ptr validated writable for 4 bytes in the caller's AS; single unaligned u32 write of the required handle_bytes.
    unsafe { core::ptr::write_unaligned(handle_ptr as *mut u32, needed); }
    err(Errno::Eoverflow)
}

/// `sys_name_to_handle_at(dirfd, path, handle, mount_id, flags)` — slot 303.
/// Resolves the target inode (AT_EMPTY_PATH ⇒ dirfd; else path, following the
/// final symlink only with AT_SYMLINK_FOLLOW), then writes an 8-byte inode FID
/// into `handle->f_handle` with `handle_type = 1` and the mount id into
/// `*mount_id` (a `u64` under AT_HANDLE_MNT_ID_UNIQUE, otherwise an `int`).
/// Errors: EINVAL (bad/conflicting flags, `handle_bytes > MAX_HANDLE_SZ`),
/// whatever the path walk reports, EOVERFLOW (buffer too small — with the
/// needed size written back, and for AT_HANDLE_CONNECTABLE, which this
/// encoder cannot satisfy), EFAULT.
/// # C: O(N_path)
pub fn sys_name_to_handle_at(args: &SyscallArgs) -> i64 {
    let dirfd = args.a0 as i32;
    let path_ptr = args.a1;
    let handle_ptr = args.a2;
    let mnt_id_ptr = args.a3;
    let opts = match name_to_handle_flags_check(args.a4 as u32) { Ok(o) => o, Err(e) => return err(e) };

    // Linux resolves the PATH before it reads `handle_bytes`, so a missing or
    // unreachable path reports ENOENT/EACCES — not the EOVERFLOW a capacity
    // probe (`handle_bytes = 0`, the documented first call of the two-step
    // protocol) would otherwise get for every path, existing or not.
    let lf = vfs::LookupFlags {
        empty: opts.empty,
        no_follow_final: !opts.follow,
        follow: opts.follow,
        ..Default::default()
    };
    let (inode, mount_id) = match crate::pathresolve::resolve_at_lookup(dirfd, path_ptr, lf) {
        Ok(p)  => (p.inode, p.mnt_id),
        Err(rv) => {
            #[cfg(feature = "debug-mount")]
            log_runtime_handle("name_to_handle_resolve", dirfd, path_ptr, rv);
            return rv;
        }
    };

    // handle->handle_bytes is the caller-supplied capacity; the header is read
    // then written back, so the struct must be readable here and writable below.
    if let Err(rv) = validate_user_buf(handle_ptr, HANDLE_HDR, 1) { return rv; }
    // SAFETY: handle_ptr validated readable for HANDLE_HDR bytes in the caller's AS by validate_user_buf; unaligned u32 read of the handle_bytes field.
    let cap = unsafe { core::ptr::read_unaligned(handle_ptr as *const u32) };
    match handle_capacity_check(cap) {
        Err(e)          => return err(e),
        Ok(Err(needed)) => return overflow(handle_ptr, needed),
        Ok(Ok(()))      => {}
    }
    // A connectable handle must encode the PARENT as well, so the decoded fd
    // has a known path. This encoder emits an inode-only FID and has no parent
    // to add, which is exactly Linux's `FILEID_INVALID` case — and Linux maps
    // that to EOVERFLOW, with the needed size written back.
    if opts.connectable { return overflow(handle_ptr, FID_LEN); }

    let fid = inode.ino().to_le_bytes();
    // 303 marks a directory handle so 304 can tell one from a disconnected
    // non-directory alias (Linux stores FILEID_IS_DIR in the same field).
    let htype = if inode.file_type() == vfs::FileType::Directory {
        HANDLE_TYPE_INO | FILEID_IS_DIR
    } else {
        HANDLE_TYPE_INO
    };
    let _ = FILEID_IS_CONNECTABLE; // never set: see the `opts.connectable` arm above
    if let Err(rv) = validate_user_buf_writable(handle_ptr, HANDLE_HDR + FID_LEN as u64, 1) {
        return rv;
    }
    // SAFETY: handle_ptr validated writable for header+FID bytes in the caller's AS; unaligned field writes of handle_bytes, handle_type, then the 8-byte inode FID.
    unsafe {
        core::ptr::write_unaligned(handle_ptr as *mut u32, FID_LEN);
        core::ptr::write_unaligned((handle_ptr + 4) as *mut i32, htype);
        for (i, b) in fid.iter().enumerate() {
            core::ptr::write_unaligned((handle_ptr + HANDLE_HDR + i as u64) as *mut u8, *b);
        }
    }

    // Linux returns the mount table id here, not st_dev/fsid, and systemd
    // compares it with mountinfo. AT_HANDLE_MNT_ID_UNIQUE selects the u64
    // never-recycled id; without it the legacy `int` field is written. Oxide
    // mints one monotonically-increasing u64 `mnt_id` that satisfies both
    // contracts, so only the WIDTH of the store differs.
    let n = if opts.unique_mnt_id { 8u64 } else { 4 };
    if let Err(rv) = validate_user_buf_writable(mnt_id_ptr, n, 1) { return rv; }
    // SAFETY: mnt_id_ptr validated writable for `n` bytes in the caller's AS; one unaligned store of the width the flags selected.
    unsafe {
        if opts.unique_mnt_id { core::ptr::write_unaligned(mnt_id_ptr as *mut u64, mount_id); }
        else { core::ptr::write_unaligned(mnt_id_ptr as *mut i32, mount_id as i32); }
    }
    #[cfg(feature = "debug-mount")]
    log_runtime_handle("name_to_handle", dirfd, path_ptr, 0);
    0
}
