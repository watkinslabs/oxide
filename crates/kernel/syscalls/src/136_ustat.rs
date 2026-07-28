// 136 ustat — the SysV "free blocks/inodes on this device" query (docs/53 §0).
// Deprecated but real: Linux still implements it in full over the superblock's
// own statfs. `fs/statfs.c`:
//
//   SYSCALL_DEFINE2(ustat, unsigned dev, struct ustat __user *ubuf)
//       vfs_ustat(new_decode_dev(dev), &sbuf)      -> EINVAL if no such super
//           user_get_super(dev) -> statfs_by_dentry(s->s_root, &sbuf)
//       memset(&tmp, 0, sizeof tmp)
//       tmp.f_tfree  = sbuf.f_bfree
//       tmp.f_tinode = sbuf.f_ffree
//       copy_to_user(ubuf, &tmp, sizeof tmp) ? -EFAULT : 0
//
// `dev` arrives in the USER `dev_t` wire form, so it must be `new_decode_dev`'d
// before it can match `SuperBlock::s_dev` (the kernel form). The ABI image is
// built by `crate::ustat_abi`, which is hosted-testable.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::validate_user_buf_writable;
use crate::ustat_abi::{USTAT_BYTES, encode_ustat};

/// `sys_ustat(dev, ubuf)` — slot 136.
/// Errors: EINVAL (no live superblock for `dev`, Linux `vfs_ustat`'s
/// `!s` arm), EIO (the superblock's `statfs` op failed — Linux propagates
/// `statfs_by_dentry`'s error), EFAULT (unwritable `ubuf`).
/// # C: O(N_sb)
pub fn sys_ustat(args: &SyscallArgs) -> i64 {
    let dev = args.a0 as u32;
    let ubuf = args.a1;

    // Linux resolves the superblock BEFORE touching `ubuf`: an unknown device
    // is EINVAL even when the output pointer is garbage.
    let kdev = vfs::new_decode_dev(dev) as u64;
    let sb = match vfs::superblock::sb_by_dev(kdev) {
        Some(sb) => sb,
        None     => return -(Errno::Einval.as_i32() as i64),
    };
    // Linux returns `statfs_by_dentry`'s own error, not a blanket EIO: a
    // frozen or shutdown filesystem reports its condition and the caller can
    // tell it from an I/O failure.
    let st = match sb.statfs() {
        Ok(st) => st,
        Err(e) => return crate::namei_common::errno_from_vfs(e),
    };

    let img = encode_ustat(st.f_bfree, st.f_ffree);
    if let Err(rv) = validate_user_buf_writable(ubuf, USTAT_BYTES as u64, 1) { return rv; }
    // SAFETY: `ubuf` validated writable for the full USTAT_BYTES span in the caller's AS by validate_user_buf_writable; byte writes need no alignment.
    unsafe {
        for (i, b) in img.iter().enumerate() {
            core::ptr::write_unaligned((ubuf + i as u64) as *mut u8, *b);
        }
    }
    0
}
