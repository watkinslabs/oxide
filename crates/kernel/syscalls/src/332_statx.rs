// 332 statx — one syscall, one file (docs/53 §0). ABI shim only: the wire
// layout, the mask rules and the validation ladder live in
// `crate::statx_abi` (no target gate, so they are unit-tested hosted).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use crate::statx_abi::{cp_statx, statx_entry, statx_validate, StatxEntry, StatxPathInfo,
    AT_EMPTY_PATH, AT_NO_AUTOMOUNT, AT_STATX_SYNC_TYPE, AT_SYMLINK_NOFOLLOW, STATX_SIZE};
use crate::stat_common::{stat_gid, stat_uid};
use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

/// Does the pathname argument mean "no path" for entry selection? Linux's
/// `getname_maybe_null` answers yes for a NULL
/// pointer, and — only with `AT_EMPTY_PATH` — for a pointer whose first byte is
/// `'\0'`. Without `AT_EMPTY_PATH` a NULL pointer is `EFAULT` from `getname`,
/// which the resolver reports. # C: O(1)
fn path_is_empty(path_ptr: u64, flags: u32) -> bool {
    if path_ptr == 0 { return true; }
    if flags & AT_EMPTY_PATH == 0 { return false; }
    if validate_user_buf(path_ptr, 1, 1).is_err() { return false; }
    // SAFETY: `validate_user_buf` proved one readable byte at `path_ptr` below
    // USER_VA_END in the active address space; a single u8 load cannot fault.
    unsafe { core::ptr::read_volatile(path_ptr as *const u8) == 0 }
}

/// `sys_statx(dirfd, path, flags, mask, statxbuf)` — slot 332.
/// # C: O(path depth)
pub fn sys_statx(args: &SyscallArgs) -> i64 {
    let dirfd     = args.a0 as i32;
    let path_ptr  = args.a1;
    let mut flags = args.a2 as u32;
    let mask      = args.a3 as u32;
    let buf       = args.a4;

    // Entry selection precedes every check: an
    // `AT_EMPTY_PATH` + empty-name + `dfd >= 0` call is `fstat`-on-dfd and
    // takes `do_statx_fd`, which strips `AT_NO_AUTOMOUNT` and — deliberately —
    // performs NO unknown-flag rejection.
    let entry = statx_entry(dirfd, path_is_empty(path_ptr, flags));
    if entry == StatxEntry::Fd { flags &= !AT_NO_AUTOMOUNT; }
    let request_mask = match statx_validate(entry, flags, mask) {
        Ok(m)  => m,
        Err(e) => return -(e.as_i32() as i64),
    };

    // Centralized `*at` resolution: AT_EMPTY_PATH → LOOKUP_EMPTY; a normal
    // statx FOLLOWS the trailing symlink (LOOKUP_FOLLOW), AT_SYMLINK_NOFOLLOW
    // does not (Linux's `statx_lookup_flags`).
    // ENOTDIR/ELOOP/EACCES/EFAULT/ENAMETOOLONG preserved by the engine.
    let nofollow = (flags & AT_SYMLINK_NOFOLLOW) != 0;
    let lf = vfs::LookupFlags {
        empty: (flags & AT_EMPTY_PATH) != 0,
        no_follow_final: nofollow,
        follow: !nofollow,
        ..Default::default()
    };
    let p = match crate::pathresolve::resolve_at_lookup_maybe_null(dirfd, path_ptr, lf) {
        Ok(p)  => p,
        Err(rv) => return rv,
    };
    let mount_root = vfs::mount::root_dentry_for_mount_id(p.mnt_id)
        .map(|root| alloc::sync::Arc::ptr_eq(&root, &p.dentry))
        .unwrap_or(false);

    // `vfs_getattr_mask` → `i_op->getattr` (default `generic_fillattr`), then
    // the VFS-level `noatime` / automount / DAX post-processing, then the
    // request-gated change cookie. `result_mask` reports exactly the fields the
    // backend could fill — never the requested set.
    let idmap = vfs::mount::idmap_for(p.mnt_id);
    // `AT_STATX_SYNC_TYPE` reaches the backend: validating it and then dropping
    // it cost a full attribute round trip on every `AT_STATX_DONT_SYNC` stat.
    let mut st = vfs::getattr::vfs_getattr_mask(&p.inode, &idmap, request_mask,
                                                flags & AT_STATX_SYNC_TYPE);
    st.uid = stat_uid(st.uid);
    st.gid = stat_gid(st.gid);
    let dev = crate::namei_common::fsid_to_dev(st.fsid);
    let rdevt = vfs::Devt::from_raw(st.rdev);
    let info = StatxPathInfo {
        mnt_id: p.mnt_id,
        mount_root,
        dev_major: crate::namei_common::dev_major(dev),
        dev_minor: crate::namei_common::dev_minor(dev),
        rdev_major: rdevt.major(),
        rdev_minor: rdevt.minor(),
    };
    let out = cp_statx(&st, &info, request_mask);

    // Linux `cp_statx` faults the output buffer LAST, after the whole lookup.
    if let Err(rv) = validate_user_buf_writable(buf, STATX_SIZE as u64, 1) { return rv; }
    // SAFETY: `validate_user_buf_writable` proved a 256-byte writable range at
    // `buf` below USER_VA_END; `copy_nonoverlapping` from a kernel-stack array
    // matches Linux `copy_to_user(buffer, &tmp, sizeof(tmp))` and needs no
    // alignment (the ABI struct is 8-aligned but userspace may pass any address).
    unsafe { core::ptr::copy_nonoverlapping(out.as_ptr(), buf as *mut u8, STATX_SIZE); }
    0
}
