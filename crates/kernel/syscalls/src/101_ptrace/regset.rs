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
use crate::s101_ptrace_user as user;

const IOVEC_BYTES: u64 = user::IOVEC_BYTES as u64;

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
        copy_regs_out(data, &u[..], frame::REGS_N * user::WORD)
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
        copy_regs_in(data, &mut u[..], frame::REGS_N * user::WORD)?;
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
    let mut iov = [0u8; user::IOVEC_BYTES];
    uaccess::copy_from_user(&mut iov, data)?;
    let (iov_base, iov_len) = user::parse_iovec(&iov);
    let n = decide::regset_len(nt, frame::ARCH, iov_len as usize)?;
    match nt {
        uapi::NT_PRSTATUS => prstatus(target, iov_base, n, write)?,
        uapi::NT_PRFPREG => {
            if write { mem::fpregs_in(target, iov_base, n)? }
            else     { mem::fpregs_out(target, iov_base, n)? }
        }
        #[cfg(target_arch = "aarch64")]
        uapi::NT_ARM_HW_BREAK => hwdebug(target, iov_base, n, write,
            hal_aarch64::hw_breakpoint::RegFile::Break)?,
        #[cfg(target_arch = "aarch64")]
        uapi::NT_ARM_HW_WATCH => hwdebug(target, iov_base, n, write,
            hal_aarch64::hw_breakpoint::RegFile::Watch)?,
        // `decide::regset_len` already rejected every other note type.
        _ => return Err(Errno::Einval),
    }
    // The clamped length goes back to `uiov->iov_len`, and ONLY when the
    // transfer itself succeeded — the reference guards the write-back with
    // `if (!ret)`, so a failed regset must not rewrite the tracer's iovec.
    uaccess::copy_to_user(data + 8, &(n as u64).to_ne_bytes())
}

/// NT_PRSTATUS transfer of the first `n` bytes of the ABI register struct.
fn prstatus(target: &Task, base: u64, n: usize, write: bool) -> Result<(), Errno> {
    if write {
        // A short iovec leaves the tail at its current value, matching
        // `copy_regset_from_user`'s partial-write semantics.
        let mut u = frame::user_regs(target).ok_or(Errno::Esrch)?;
        copy_regs_in(base, &mut u[..], n)?;
        frame::set_user_regs(target, &u)
    } else {
        let u = frame::user_regs(target).ok_or(Errno::Esrch)?;
        copy_regs_out(base, &u[..], n)
    }
}

/// Copy the first `n` BYTES of `regs` out. Byte- rather than word-granular:
/// `copy_regset_to_user` transfers whatever `iov_len` asked for, so an
/// `iov_len` of 12 must move 12 bytes, not one word and a dropped remainder.
/// The chunking plan is the ungated `user::regs_out`; this closure is only the
/// fault-recovering store.
fn copy_regs_out(dst: u64, regs: &[u64], n: usize) -> Result<(), Errno> {
    if n == 0 { return Ok(()); }
    if crate::userbuf::validate_user_buf_writable(dst, n as u64, 1).is_err() {
        return Err(Errno::Efault);
    }
    user::regs_out(regs, n, |off, b| uaccess::copy_to_user(dst + off as u64, b))
}

/// Copy the first `n` bytes IN over `regs`, leaving the untransferred tail —
/// including the tail of a trailing partial word — at its current value.
fn copy_regs_in(src: u64, regs: &mut [u64], n: usize) -> Result<(), Errno> {
    if n == 0 { return Ok(()); }
    if crate::userbuf::validate_user_buf(src, n as u64, 1).is_err() {
        return Err(Errno::Efault);
    }
    user::regs_in(regs, n, |off, b| uaccess::copy_from_user(b, src + off as u64))
}

/// `NT_ARM_HW_BREAK` / `NT_ARM_HW_WATCH` — arm64's hardware breakpoint and
/// watchpoint register files, exchanged as a `struct user_hwdebug_state`.
/// This is the interface `gdb`'s `hbreak` and `watch` drive; arm64 has no
/// `struct user` debug window for them to use instead.
///
/// The header's `dbg_info` reports the debug architecture version and the
/// number of slots THIS machine implements, read from the CPU's own feature
/// register. The buffer is always the full 16 slots regardless — the
/// implemented count travels in the header, not in the length.
///
/// Transferred one slot at a time rather than through a `struct`-sized stack
/// buffer: the whole structure is 264 bytes and this runs on the syscall path,
/// whose deepest aarch64 chain has no room for it.
///
/// A write validates every slot into a scratch copy FIRST and installs the
/// result only if all of them pass, so a rejected slot cannot leave the task
/// holding half a debugger's request. The layout arithmetic belongs to the
/// HAL; this shim only moves bytes and reports errno.
/// # C: O(N_slots)
#[cfg(target_arch = "aarch64")]
fn hwdebug(target: &Task, base: u64, n: usize, write: bool,
           file: hal_aarch64::hw_breakpoint::RegFile) -> Result<(), Errno> {
    use hal_aarch64::hw_breakpoint::layout;
    if n == 0 { return Ok(()); }
    let ok = if write { crate::userbuf::validate_user_buf(base, n as u64, 1).is_ok() }
             else     { crate::userbuf::validate_user_buf_writable(base, n as u64, 1).is_ok() };
    if !ok { return Err(Errno::Efault); }
    if write {
        let mut st = sched::debugreg::arm::snapshot(target);
        for idx in 0..layout::REGSET_SLOTS {
            // A short iovec leaves the remaining slots at their current value,
            // matching `copy_regset_from_user`'s partial-write semantics.
            if layout::slot_ctrl_off(idx) + 4 > n { break; }
            let addr = read_u64(base, layout::slot_addr_off(idx))?;
            let ctrl = read_u32(base, layout::slot_ctrl_off(idx))?;
            st.set_addr(file, idx, addr).map_err(|_| Errno::Einval)?;
            st.set_ctrl(file, idx, ctrl).map_err(|_| Errno::Einval)?;
        }
        sched::debugreg::arm::store(target, &st);
        return Ok(());
    }
    let st = sched::debugreg::arm::snapshot(target);
    if layout::DBG_INFO_OFF + 4 <= n {
        write_u32(base, layout::DBG_INFO_OFF, sched::debugreg::arm::dbg_info(file))?;
    }
    if layout::HDR_PAD_OFF + 4 <= n { write_u32(base, layout::HDR_PAD_OFF, 0)?; }
    for idx in 0..layout::REGSET_SLOTS {
        let (addr, ctrl) = st.get(file, idx).unwrap_or((0, 0));
        if layout::slot_addr_off(idx) + 8 <= n { write_u64(base, layout::slot_addr_off(idx), addr)?; }
        if layout::slot_ctrl_off(idx) + 4 <= n { write_u32(base, layout::slot_ctrl_off(idx), ctrl)?; }
        if layout::slot_pad_off(idx)  + 4 <= n { write_u32(base, layout::slot_pad_off(idx), 0)?; }
    }
    Ok(())
}

/// Single-field user reads/writes at an offset inside a range the caller
/// already validated. Kept tiny and separate so the transfer above needs no
/// buffer; each goes through `uaccess`, so a page unmapped under the transfer
/// is EFAULT rather than a kernel fault.
#[cfg(target_arch = "aarch64")]
fn read_u64(base: u64, off: usize) -> Result<u64, Errno> {
    let mut b = [0u8; 8];
    uaccess::copy_from_user(&mut b, base + off as u64)?;
    Ok(u64::from_ne_bytes(b))
}

#[cfg(target_arch = "aarch64")]
fn read_u32(base: u64, off: usize) -> Result<u32, Errno> {
    let mut b = [0u8; 4];
    uaccess::copy_from_user(&mut b, base + off as u64)?;
    Ok(u32::from_ne_bytes(b))
}

#[cfg(target_arch = "aarch64")]
fn write_u64(base: u64, off: usize, v: u64) -> Result<(), Errno> {
    uaccess::copy_to_user(base + off as u64, &v.to_ne_bytes())
}

#[cfg(target_arch = "aarch64")]
fn write_u32(base: u64, off: usize, v: u32) -> Result<(), Errno> {
    uaccess::copy_to_user(base + off as u64, &v.to_ne_bytes())
}
