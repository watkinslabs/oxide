// 246 kexec_load — one syscall, one file (docs/53 §0).
//
// ABI shim only: the permission rule, the flag masks, the segment-list
// validation and the whole staging algorithm live in the `kexec` crate, where
// they are host-tested. This file copies the segment array in and encodes the
// result.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::kexec_abi::{encode, errno_for, segment_array_bytes};

/// Read `dst.len()` bytes of user memory through the exception table.
fn read_user(dst: &mut [u8], addr: u64) -> Result<(), ()> {
    uaccess::copy_from_user(dst, addr).map_err(|_| ())
}

/// `kexec_load(entry, nr_segments, segments, flags)` per Linux `kexec_load(2)`.
///
/// Order: `kexec_load_permitted` (EPERM), the flag word (EINVAL), the
/// `KEXEC_SEGMENT_MAX` cap (EINVAL), the architecture field (EINVAL), the
/// segment array copy (EFAULT), then the load itself — the kexec lock (EBUSY),
/// the segment list (EADDRNOTAVAIL / EINVAL) and the staging (ENOMEM / EFAULT).
///
/// `nr_segments == 0` unloads whichever image `flags` names and succeeds
/// whether or not one was staged.
/// # C: O(total memsz)
pub fn sys_kexec_load(args: &SyscallArgs) -> i64 {
    let (entry, nr_segments, seg_ptr, flags) = (args.a0, args.a1, args.a2, args.a3);
    let cur = match sched::live::current() { Some(c) => c, None => return errno_for(kexec::Error::Perm) };
    let permitted = kexec::load_permitted(cur.has_cap(sched::cap::SYS_BOOT));
    if let Err(e) = kexec::kexec_load_check(permitted, nr_segments, flags) { return errno_for(e); }
    if let Err(e) = kexec::arch_ok(flags) { return errno_for(e); }
    if segment_array_bytes(nr_segments).is_none() { return -(Errno::Einval.as_i32() as i64); }

    // `memdup_array_user`: the whole array is copied BEFORE anything is
    // validated or staged, so a caller cannot rewrite a segment between the
    // check that accepted it and the copy that uses it.
    let mut segments = alloc::vec::Vec::with_capacity(nr_segments as usize);
    for i in 0..nr_segments {
        let mut raw = [0u8; kexec::KEXEC_SEGMENT_SIZE];
        let at = seg_ptr.wrapping_add(i * kexec::KEXEC_SEGMENT_SIZE as u64);
        if uaccess::copy_from_user(&mut raw, at).is_err() { return -(Errno::Efault.as_i32() as i64); }
        segments.push(kexec::KexecSegment::from_bytes(&raw));
    }

    let src = kexec::UserSource { read: read_user };
    let mut frames = kexec::PmmFrames;
    encode(kexec::do_kexec_load(&mut frames, entry, segments, flags,
                                kexec::Limits::default(), &src))
}
