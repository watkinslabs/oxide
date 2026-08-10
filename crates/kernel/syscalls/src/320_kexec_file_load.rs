// 320 kexec_file_load — one syscall, one file (docs/53 §0).
//
// ABI shim only: the flag mask, the ladder and the loader registry live in
// `kexec::file_load`. This file reads the two descriptors and the command line
// and encodes the result.

#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::kexec_abi::{encode, errno_for};

/// Read a whole file through a descriptor, bounded by `KEXEC_FILE_SIZE_MAX`.
///
/// `EBADF` for a descriptor that is not open, `EIO` for a read that fails,
/// `ENOMEM` for a file over the ceiling — the reference's
/// `kernel_read_file_from_fd` errnos.
/// # C: O(file size)
fn read_fd(fd: i32) -> kexec::KResult<Vec<u8>> {
    let cur = sched::live::current().ok_or(kexec::Error::BadFd)?;
    // SAFETY: the running task on this CPU is the sole reader of its own fd
    // table slot for the duration of this syscall.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(kexec::Error::BadFd)?.clone();
    let file = fdt.get(fd).map_err(|_| kexec::Error::BadFd)?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut off = 0u64;
    loop {
        match file.inode().read(off, &mut chunk) {
            Ok(0) => break,
            Ok(n) => { buf.extend_from_slice(&chunk[..n]); off += n as u64; }
            Err(_) => return Err(kexec::Error::Nomem),
        }
        if buf.len() as u64 > kexec::KEXEC_FILE_SIZE_MAX { return Err(kexec::Error::Nomem); }
    }
    Ok(buf)
}

/// `kexec_file_load(kernel_fd, initrd_fd, cmdline_len, cmdline, flags)` per
/// Linux `kexec_file_load(2)`.
///
/// Order: `kexec_load_permitted` (EPERM), the exact flag mask (EINVAL), the
/// kexec lock (EBUSY), the `KEXEC_FILE_UNLOAD` short-circuit, the kernel file
/// (EBADF / ENOMEM), the initramfs unless `KEXEC_FILE_NO_INITRAMFS`, the
/// command line (EFAULT then EINVAL), then the loader probe (ENOEXEC).
///
/// No signature verification is performed or claimed: with signature checking
/// unconfigured the reference runs none either, and this kernel has no keyring
/// to verify against. See `kexec::validate::signature_check_required`.
/// # C: O(kernel + initramfs bytes)
pub fn sys_kexec_file_load(args: &SyscallArgs) -> i64 {
    let (kernel_fd, initrd_fd) = (args.a0 as i32, args.a1 as i32);
    let (cmdline_len, cmdline_ptr, flags) = (args.a2, args.a3, args.a4);
    let cur = match sched::live::current() { Some(c) => c, None => return errno_for(kexec::Error::Perm) };
    let permitted = kexec::load_permitted(cur.has_cap(sched::cap::SYS_BOOT), kexec::file_image_type(flags));
    if let Err(e) = kexec::kexec_file_load_check(permitted, flags) { return errno_for(e); }
    if cmdline_len > kexec::KEXEC_FILE_SIZE_MAX { return -(Errno::Einval.as_i32() as i64); }

    let mut frames = kexec::PmmFrames;
    encode(kexec::kexec_file_load(&mut frames, flags, || {
        let kernel = read_fd(kernel_fd)?;
        let initrd = if flags & kexec::KEXEC_FILE_NO_INITRAMFS != 0 {
            Vec::new()
        } else {
            read_fd(initrd_fd)?
        };
        let mut cmdline = alloc::vec![0u8; cmdline_len as usize];
        if cmdline_len != 0 && uaccess::copy_from_user(&mut cmdline, cmdline_ptr).is_err() {
            return Err(kexec::Error::Fault);
        }
        Ok(kexec::FileImage { kernel, initrd, cmdline })
    }))
}
