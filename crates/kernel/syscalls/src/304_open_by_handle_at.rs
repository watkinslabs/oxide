// open_by_handle_at(2) per `15§5` / `16` — the reverse of name_to_handle_at.
// Reopens a file from the exportable handle that 303 emitted (an 8-byte inode
// FID, handle_type = 1). Linux resolves it via exportfs `fh_to_dentry`: the
// `mountdirfd` identifies the filesystem (its superblock), the FID supplies the
// inode number, and the inode is reconstructed/looked up on that superblock.
//
// FID -> inode mechanism here: the anchor path -> its inode's `i_sb()` -> the
// superblock the anchor's filesystem owns -> `sb.ilookup(ino)`. A resident
// inode resolves; one that is gone -> ESTALE, exactly Linux's `fh_to_dentry`
// staleness contract. The reopened File is built over a disconnected dentry
// alias (`d_obtain_alias`, Linux exportfs), honoring the open flags, and
// installed via the rlimit-aware fd allocator.
//
// ORDER matters and follows Linux `handle_to_path`: the handle header is
// validated FIRST (EINVAL), then the mount fd is resolved (EBADF), and only
// then is `may_decode_fh`'s CAP_DAC_READ_SEARCH consulted (EPERM). Checking the
// capability first told an unprivileged caller "permission denied" for a
// malformed handle or a closed fd — two errors privilege would never have
// fixed.
//
// Header/flag decisions live in `crate::handle_policy` (hosted-tested).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::{File, OpenFlags};

use crate::handle_policy::{FID_LEN, HANDLE_HDR, handle_header_check, header_is_our_fid};
use crate::userbuf::validate_user_buf;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `sys_open_by_handle_at(mountdirfd, file_handle, flags)` — slot 304.
/// Errors: EINVAL (malformed handle header), EBADF (bad `mountdirfd`), EPERM
/// (no CAP_DAC_READ_SEARCH), ESTALE (handle from a foreign encoder, or an
/// inode no longer resident on the anchor's superblock).
/// # C: O(log N_ino)
pub fn sys_open_by_handle_at(args: &SyscallArgs) -> i64 {
    let mountdirfd = args.a0 as i32;
    let handle_ptr = args.a1;
    let flags = args.a2 as u32;

    // 1. Handle header — Linux `copy_from_user` + the EINVAL ladder, before any
    //    fd lookup or capability check.
    if let Err(rv) = validate_user_buf(handle_ptr, HANDLE_HDR, 1) { return rv; }
    // SAFETY: handle_ptr validated readable for the 8-byte header in the caller's AS by validate_user_buf; unaligned reads of handle_bytes(u32) then handle_type(i32).
    let (bytes, htype) = unsafe {
        (core::ptr::read_unaligned(handle_ptr as *const u32),
         core::ptr::read_unaligned((handle_ptr + 4) as *const i32))
    };
    if let Err(e) = handle_header_check(bytes, htype) { return err(e); }

    // 2. Anchor — Linux `get_path_anchor(mountdirfd)`. AT_FDCWD is a valid
    //    anchor (the cwd's mount), not a bad fd; the empty-path resolver is the
    //    one place that mapping lives.
    let anchor = match crate::pathresolve::resolve_at_lookup_maybe_null(
        mountdirfd, 0, vfs::LookupFlags { empty: true, ..Default::default() })
    {
        Ok(p)  => p,
        Err(_) => return err(Errno::Ebadf),
    };

    // 3. `may_decode_fh` — the handle sidesteps path-walk permission, so only a
    //    caller that may search any path may resolve one.
    let cur = match sched::live::current() { Some(c) => c, None => return err(Errno::Ebadf) };
    if !cur.has_cap(sched::cap::DAC_READ_SEARCH) { return err(Errno::Eperm); }

    // 4. Decode. A well-formed handle from a different encoder is not EINVAL:
    //    Linux's `exportfs_decode_fh_raw` reports ESTALE for anything it cannot
    //    turn back into a dentry, because the handle may simply describe an
    //    object this filesystem no longer has.
    if !header_is_our_fid(bytes, htype) { return err(Errno::Estale); }
    if let Err(rv) = validate_user_buf(handle_ptr + HANDLE_HDR, FID_LEN as u64, 1) { return rv; }
    // SAFETY: f_handle region validated readable for FID_LEN bytes in the caller's AS; byte-wise unaligned reads of the 8-byte little-endian inode FID.
    let mut fid = [0u8; FID_LEN as usize];
    for (i, b) in fid.iter_mut().enumerate() {
        *b = unsafe { core::ptr::read_unaligned((handle_ptr + HANDLE_HDR + i as u64) as *const u8) };
    }
    let ino = u64::from_le_bytes(fid);

    let sb = match anchor.inode.i_sb() {
        Some(s) => s,
        None    => return err(Errno::Estale),
    };
    // exportfs `fh_to_dentry`: a resident inode on this sb resolves; a gone /
    // evicted inode -> ESTALE (the on-disk inode cannot be re-read by ino here
    // — no `s_export_op` backend hook — so non-resident == stale).
    let inode = match sb.ilookup(ino) { Some(i) => i, None => return err(Errno::Estale) };

    // DAC + EROFS enforcement against the requested access mode (Linux
    // `do_handle_open` -> `vfs_open` -> `may_open`), through the mount the
    // handle was decoded on.
    let mnt_id = anchor.mnt_id;
    if let Some(rv) = crate::open_common::enforce_open_perm(&inode, mnt_id, flags, false) {
        return rv;
    }
    // Disconnected dentry alias (Linux exportfs `d_obtain_alias`): reuses a live
    // alias if the inode already has one, else allocates an anonymous one.
    let dentry = vfs::dcache::d_obtain_alias(inode.clone());
    let oflags = OpenFlags::from_bits_truncate(flags) - OpenFlags::O_CLOEXEC;
    let file_cred = match crate::pathresolve::file_cred_for(&cur) {
        Some(cred) => cred, None => return err(Errno::Esrch),
    };
    let file = File::new_at(inode, dentry, oflags, mnt_id, file_cred);
    if let Err(e) = file.open_hook() { return -(e as i64); }
    match fdt_alloc(cur, file, flags) { Ok(fd) => fd, Err(rv) => rv }
}

/// Install the reopened file under the RLIMIT_NOFILE soft cap, honoring
/// O_CLOEXEC. # C: O(1)
fn fdt_alloc(cur: &sched::Task, file: alloc::sync::Arc<File>, flags: u32) -> Result<i64, i64> {
    // SAFETY: fd_table slot single-mutator per `13§5`; running task on this CPU; Arc clone.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return Err(err(Errno::Ebadf)),
    };
    match fdt.alloc_limit(file, cur.nofile_soft()) {
        Ok(fd) => {
            if (flags & OpenFlags::O_CLOEXEC.bits()) != 0 {
                if let Err(e) = fdt.set_cloexec(fd, true) { return Err(-(e as i64)); }
            }
            Ok(fd as i64)
        }
        Err(e) => Err(-(e as i64)),
    }
}
