// name_to_handle_at(2) per `15§5` / `16`. Linux exportable file
// handles: encode inode identity so userspace can test two paths for
// same-inode-ness without holding fds open. systemd's
// running_in_chroot() depends on it — it FID-probes /proc/1/root and /
// and compares the returned handles (an ENOSYS stub forces a fallback
// path that wrongly concludes "chrooted" and freezes PID1).
//
// The handle we emit is the 8-byte inode number (FILEID-style); the
// mount id is a single constant since v1 has one visible mount domain.
// Same inode -> identical handle -> systemd sees the same file.
// open_by_handle_at (the reverse) is implemented in
// 304_open_by_handle_at.rs (D47): it decodes this same 8-byte inode FID
// and resolves it on mount_fd's superblock via ilookup(ino), gated on
// CAP_DAC_READ_SEARCH.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

// struct file_handle { __u32 handle_bytes; int handle_type; unsigned char f_handle[]; }
// f_handle starts at offset 8; we write an 8-byte inode FID there.
const FID_LEN: u32 = 8;
const HANDLE_HDR: usize = 8; // handle_bytes(4) + handle_type(4)

/// `sys_name_to_handle_at(dirfd, path, handle, mount_id, flags)` — slot 303.
/// Resolves the target inode (AT_EMPTY_PATH ⇒ dirfd; else path, following
/// the final symlink unless AT_SYMLINK_FOLLOW is clear), then writes an
/// 8-byte inode FID into `handle->f_handle` with `handle_type = 1` and a
/// constant `*mount_id`. Returns EOVERFLOW (with `handle_bytes` set to
/// the needed size) when the caller's buffer is too small — the Linux
/// grow-and-retry protocol.
/// # C: O(N_path)
pub fn sys_name_to_handle_at(args: &SyscallArgs) -> i64 {
    const AT_EMPTY_PATH: u32 = 0x1000;
    const AT_SYMLINK_FOLLOW: u32 = 0x400;
    let dirfd = args.a0 as i32;
    let path_ptr = args.a1;
    let handle_ptr = args.a2;
    let mnt_id_ptr = args.a3;
    let flags = args.a4 as u32;

    // handle->handle_bytes is read first (caller-supplied capacity), then
    // the full header+FID is written back, so the struct must be R+W.
    if let Err(rv) = validate_user_buf(handle_ptr, HANDLE_HDR as u64, 1) { return rv; }
    // SAFETY: handle_ptr validated readable for HANDLE_HDR bytes in the caller's AS by validate_user_buf above; aligned u32 read of the handle_bytes field.
    let cap = unsafe { core::ptr::read_volatile(handle_ptr as *const u32) };
    if cap < FID_LEN {
        // Tell the caller the size we need and let its loop grow + retry.
        if let Err(rv) = validate_user_buf_writable(handle_ptr, 4, 1) { return rv; }
        // SAFETY: handle_ptr validated writable for 4 bytes; write the required handle_bytes per the EOVERFLOW retry protocol.
        unsafe { core::ptr::write_volatile(handle_ptr as *mut u32, FID_LEN); }
        return -(Errno::Eoverflow.as_i32() as i64);
    }

    // Centralized `*at` resolution: AT_EMPTY_PATH → LOOKUP_EMPTY (empty/NULL
    // path operates on the dirfd, ENOENT without it). name_to_handle_at FOLLOWS
    // the final symlink only with AT_SYMLINK_FOLLOW; otherwise it does not.
    let nofollow = (flags & AT_SYMLINK_FOLLOW) == 0;
    let lf = vfs::LookupFlags {
        empty: (flags & AT_EMPTY_PATH) != 0,
        no_follow_final: nofollow,
        follow: !nofollow,
        ..Default::default()
    };
    let (inode, mount_id) = match crate::pathresolve::resolve_at_lookup(dirfd, path_ptr, lf) {
        Ok(p)  => (p.inode, p.mnt_id as i32),
        Err(rv) => return rv,
    };

    let fid = inode.ino().to_le_bytes();
    if let Err(rv) = validate_user_buf_writable(handle_ptr, HANDLE_HDR as u64 + FID_LEN as u64, 1) {
        return rv;
    }
    // SAFETY: handle_ptr validated writable for header+FID bytes in the caller's AS; field-by-field volatile writes of handle_bytes, handle_type, then the 8-byte inode FID.
    unsafe {
        core::ptr::write_volatile(handle_ptr as *mut u32, FID_LEN);
        core::ptr::write_volatile((handle_ptr + 4) as *mut i32, 1); // handle_type (nonzero)
        for (i, b) in fid.iter().enumerate() {
            core::ptr::write_volatile((handle_ptr + HANDLE_HDR as u64 + i as u64) as *mut u8, *b);
        }
    }
    if mnt_id_ptr != 0 && mnt_id_ptr < USER_VA_END {
        if validate_user_buf_writable(mnt_id_ptr, 4, 1).is_ok() {
            // Linux returns the mount table id here, not st_dev/fsid. systemd
            // compares this with mountinfo and asserts it is non-negative.
            // SAFETY: mnt_id_ptr validated writable for 4 bytes; single aligned i32 write of the mount id.
            unsafe { core::ptr::write_volatile(mnt_id_ptr as *mut i32, mount_id); }
        }
    }
    0
}
