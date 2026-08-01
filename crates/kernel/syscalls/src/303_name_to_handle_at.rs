// name_to_handle_at(2) per `15§5` / `16`. Exportable file handles: encode an
// object's identity so userspace can compare two paths for same-object-ness
// without holding fds open, and so `open_by_handle_at(2)` (304) can reopen it
// with no path walk at all.
//
// The handle carries `(ino, i_generation)`, never a bare inode number: an inode
// number alone is reusable, so a handle minted against a deleted file would
// silently open whatever later inherited its number. `AT_HANDLE_CONNECTABLE`
// additionally encodes the PARENT's identity for a non-directory, which is what
// lets 304 hand back a dentry with a real name instead of an anonymous alias.
//
// ABI constants, flag masks, the FID codec and the capacity protocol live in
// `crate::handle_policy` (hosted-tested); this file is the shim (docs/53).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::handle_policy::{FID_LEN_PARENT, FILEID_IS_CONNECTABLE, FILEID_IS_DIR, Fid, HANDLE_HDR,
    encode_fid, encoded_fid_len, handle_capacity_check, name_to_handle_flags_check};
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

/// Write `handle_bytes` back and report EOVERFLOW — the grow-and-retry
/// protocol: on an undersized buffer the kernel stores the size the encoder
/// needs, copies out only the fixed header, and fails, so the caller can
/// reallocate and retry.
/// # C: O(1)
fn overflow(handle_ptr: u64, needed: u32) -> i64 {
    if let Err(rv) = validate_user_buf_writable(handle_ptr, 4, 1) { return rv; }
    // SAFETY: handle_ptr validated writable for 4 bytes in the caller's AS; single unaligned u32 write of the required handle_bytes.
    unsafe { core::ptr::write_unaligned(handle_ptr as *mut u32, needed); }
    err(Errno::Eoverflow)
}

/// `sys_name_to_handle_at(dirfd, path, handle, mount_id, flags)` — slot 303.
/// Resolves the target inode (AT_EMPTY_PATH ⇒ dirfd; else path, following the
/// final symlink only with AT_SYMLINK_FOLLOW), writes its `(ino, generation)`
/// FID into `handle->f_handle` — plus the parent's under AT_HANDLE_CONNECTABLE
/// for a non-directory — and the mount id into `*mount_id` (a `u64` under
/// AT_HANDLE_MNT_ID_UNIQUE, otherwise an `int`).
/// Errors: EINVAL (bad/conflicting flags, `handle_bytes > MAX_HANDLE_SZ`),
/// EOPNOTSUPP (the filesystem cannot decode what it would encode), whatever the
/// path walk reports, EOVERFLOW (buffer too small, with the needed size written
/// back), ESTALE (a connectable request for an object with no reachable
/// parent), EFAULT.
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
    let path = match crate::pathresolve::resolve_at_lookup(dirfd, path_ptr, lf) {
        Ok(p)  => p,
        Err(rv) => {
            #[cfg(feature = "debug-mount")]
            log_runtime_handle("name_to_handle_resolve", dirfd, path_ptr, rv);
            return rv;
        }
    };
    let inode = path.inode.clone();
    let mount_id = path.mnt_id;
    let is_dir = inode.file_type() == vfs::FileType::Directory;

    // A filesystem that cannot turn its own handles back into inodes must not
    // mint one a caller will later fail to open (`exportfs_can_encode_fh`).
    let sb = inode.i_sb();
    if let Some(sb) = sb.as_ref() {
        if !vfs::export::can_encode_fh(sb) { return err(Errno::Eopnotsupp); }
    }

    // handle->handle_bytes is the caller-supplied capacity; the header is read
    // then written back, so the struct must be readable here and writable below.
    if let Err(rv) = validate_user_buf(handle_ptr, HANDLE_HDR, 1) { return rv; }
    // SAFETY: handle_ptr validated readable for HANDLE_HDR bytes in the caller's AS by validate_user_buf; unaligned u32 read of the handle_bytes field.
    let cap = unsafe { core::ptr::read_unaligned(handle_ptr as *const u32) };
    // The WIDTH is the filesystem's, not the VFS's: a kernfs-backed pseudo-fs
    // mints an 8-byte node-id handle, and a caller that sizes its buffer to
    // that width without running the grow-and-retry protocol would otherwise
    // get EOVERFLOW from every call.
    let needed = match sb.as_ref() {
        Some(sb) => sb.s_op.export_fid_len(opts.connectable, is_dir),
        None     => encoded_fid_len(opts.connectable, is_dir),
    };
    match handle_capacity_check(cap, needed) {
        Err(e)          => return err(e),
        Ok(Err(needed)) => return overflow(handle_ptr, needed),
        Ok(Ok(()))      => {}
    }

    // A connectable NON-directory needs its parent's identity in the handle;
    // a directory does not, because it has exactly one dentry and decode
    // reconnects it by walking `..`. AT_EMPTY_PATH is already rejected
    // alongside AT_HANDLE_CONNECTABLE, so the resolved dentry always has a
    // parent here unless it is a filesystem root.
    let parent = if opts.connectable && !is_dir {
        let pi = path.dentry.parent().and_then(|p| p.inode());
        match pi {
            Some(p) => Some((p.ino(), p.i_generation())),
            None    => return err(Errno::Estale),
        }
    } else { None };

    let mut fid_buf = [0u8; FID_LEN_PARENT as usize];
    let (fid_len, fid_type) = match sb.as_ref() {
        Some(sb) => sb.s_op.export_encode_fh(&inode, parent, &mut fid_buf),
        None     => encode_fid(&Fid {
            ino: inode.ino(), generation: inode.i_generation(), parent }, &mut fid_buf),
    };
    // The user flags ride in `handle_type` so 304 knows how to decode without
    // out-of-band state: CONNECTABLE says "reconnect me", IS_DIR says which of
    // the two reconnect shapes applies.
    let mut htype = fid_type;
    if opts.connectable {
        htype |= FILEID_IS_CONNECTABLE;
        if is_dir { htype |= FILEID_IS_DIR; }
    }

    if let Err(rv) = validate_user_buf_writable(handle_ptr, HANDLE_HDR + fid_len as u64, 1) {
        return rv;
    }
    // SAFETY: handle_ptr validated writable for header+FID bytes in the caller's AS; unaligned field writes of handle_bytes, handle_type, then the FID payload.
    unsafe {
        core::ptr::write_unaligned(handle_ptr as *mut u32, fid_len);
        core::ptr::write_unaligned((handle_ptr + 4) as *mut i32, htype);
        for (i, b) in fid_buf[..fid_len as usize].iter().enumerate() {
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
