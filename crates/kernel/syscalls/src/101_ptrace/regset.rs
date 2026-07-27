// PTRACE_GETREGS/SETREGS (x86_64 only) and PTRACE_GETREGSET/SETREGSET.
//
// GETREGSET's `data` is a `struct iovec *`, NOT a register buffer: Linux
// `ptrace_request` copies `{iov_base, iov_len}` in, clamps `iov_len` to the
// regset size, transfers through `iov_base`, then writes the achieved length
// back to `uiov->iov_len`. Treating `data` as the buffer (what this file used
// to do) both scribbled the tracer's iovec and made GETREGSET return garbage
// — and GETREGSET is the ONLY general-register interface arm64 has.

#![cfg(target_os = "oxide-kernel")]

use sched::Task;
use syscall::errno::Errno;
use super::{frame, mem};
use crate::s101_ptrace_decide as decide;
use crate::s101_ptrace_uapi as uapi;

const IOVEC_BYTES: u64 = 16;

/// PTRACE_GETREGS — x86_64's `struct user_regs_struct` copy-out. arm64 has
/// no such request; its `arch_ptrace` falls through to `ptrace_request`,
/// whose default arm is EIO.
/// # C: O(1)
pub fn getregs(target: &Task, data: u64) -> Result<(), Errno> {
    #[cfg(target_arch = "aarch64")]
    { let _ = (target, data); return Err(Errno::Eio); }
    #[cfg(target_arch = "x86_64")]
    {
        let u = frame::user_regs(target).ok_or(Errno::Esrch)?;
        copy_regs_out(data, &u[..])
    }
}

/// PTRACE_SETREGS — x86_64 only, as above.
/// # C: O(1)
pub fn setregs(target: &Task, data: u64) -> Result<(), Errno> {
    #[cfg(target_arch = "aarch64")]
    { let _ = (target, data); return Err(Errno::Eio); }
    #[cfg(target_arch = "x86_64")]
    {
        let mut u = [0u64; frame::REGS_N];
        copy_regs_in(data, &mut u[..])?;
        frame::set_user_regs(target, &u)
    }
}

/// PTRACE_GETREGSET / PTRACE_SETREGSET. `nt` is the `NT_*` note type in
/// `addr`; `data` points at the tracer's `struct iovec`.
/// # C: O(iov_len)
pub fn regset(target: &Task, nt: u64, data: u64, write: bool) -> Result<(), Errno> {
    if crate::userbuf::validate_user_buf_writable(data, IOVEC_BYTES, 1).is_err() {
        return Err(Errno::Efault);
    }
    // SAFETY: `data..data+16` validated as a mapped writable range in the caller's AS; Linux `__get_user` on `struct iovec` is likewise unaligned-tolerant.
    let (iov_base, iov_len) = unsafe {
        (core::ptr::read_unaligned(data as *const u64),
         core::ptr::read_unaligned((data + 8) as *const u64))
    };
    let n = decide::regset_len(nt, frame::ARCH, iov_len as usize)?;
    match nt {
        uapi::NT_PRSTATUS => prstatus(target, iov_base, n, write)?,
        uapi::NT_PRFPREG => {
            if write { mem::fpregs_in(target, iov_base, n)? }
            else     { mem::fpregs_out(target, iov_base, n)? }
        }
        // `decide::regset_len` already rejected every other note type.
        _ => return Err(Errno::Einval),
    }
    // SAFETY: `data+8..data+16` is inside the 16-byte iovec validated writable above; Linux writes the achieved length back the same way.
    unsafe { core::ptr::write_unaligned((data + 8) as *mut u64, n as u64); }
    Ok(())
}

/// NT_PRSTATUS transfer of the first `n` bytes of the ABI register struct.
fn prstatus(target: &Task, base: u64, n: usize, write: bool) -> Result<(), Errno> {
    if write {
        // A short iovec leaves the tail at its current value, matching
        // `copy_regset_from_user`'s partial-write semantics.
        let mut u = frame::user_regs(target).ok_or(Errno::Esrch)?;
        copy_regs_in(base, &mut u[..n / 8])?;
        frame::set_user_regs(target, &u)
    } else {
        let u = frame::user_regs(target).ok_or(Errno::Esrch)?;
        copy_regs_out(base, &u[..n / 8])
    }
}

fn copy_regs_out(dst: u64, regs: &[u64]) -> Result<(), Errno> {
    let bytes = (regs.len() * 8) as u64;
    if bytes == 0 { return Ok(()); }
    if crate::userbuf::validate_user_buf_writable(dst, bytes, 1).is_err() {
        return Err(Errno::Efault);
    }
    // SAFETY: `dst..dst+bytes` validated as a mapped writable range in the caller's AS; unaligned quadword stores, as Linux `copy_to_user` permits.
    unsafe {
        for (i, v) in regs.iter().enumerate() {
            core::ptr::write_unaligned((dst + (i as u64) * 8) as *mut u64, *v);
        }
    }
    Ok(())
}

fn copy_regs_in(src: u64, regs: &mut [u64]) -> Result<(), Errno> {
    let bytes = (regs.len() * 8) as u64;
    if bytes == 0 { return Ok(()); }
    if crate::userbuf::validate_user_buf(src, bytes, 1).is_err() {
        return Err(Errno::Efault);
    }
    // SAFETY: `src..src+bytes` validated as a mapped readable range in the caller's AS; unaligned quadword loads, as Linux `copy_from_user` permits.
    unsafe {
        for (i, v) in regs.iter_mut().enumerate() {
            *v = core::ptr::read_unaligned((src + (i as u64) * 8) as *const u64);
        }
    }
    Ok(())
}
