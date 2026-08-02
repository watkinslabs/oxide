// PTRACE_PEEKSIGINFO, PTRACE_GET_SYSCALL_INFO, PTRACE_SET_SYSCALL_INFO,
// PTRACE_SECCOMP_GET_FILTER, PTRACE_SECCOMP_GET_METADATA and
// PTRACE_GET_RSEQ_CONFIGURATION — the live half only. Every layout, op code
// and validation rule is in the ungated siblings `sysinfo.rs` / `decide.rs`;
// what remains here is reading the tracee's state and copying bytes.

#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use sched::Task;
use syscall::errno::Errno;

use crate::s101_ptrace_decide as decide;
use crate::s101_ptrace_sysinfo as sysinfo;
use crate::s101_ptrace_uapi as uapi;

/// PTRACE_PEEKSIGINFO. `addr` points at a `struct ptrace_peeksiginfo_args`;
/// `data` at an array of `siginfo_t`. Returns the NUMBER of records copied —
/// a positive count, not zero — and stops early at the end of the queue.
/// A fault after at least one record still reports that partial count, which
/// is Linux's `if (i > 0) return i;`.
/// # C: O(off + nr)
pub fn peeksiginfo(target: &Task, addr: u64, data: u64) -> Result<i64, Errno> {
    if crate::userbuf::validate_user_buf(addr, uapi::PEEKSIGINFO_ARGS_BYTES, 1).is_err() {
        return Err(Errno::Efault);
    }
    // SAFETY: `addr..addr+16` validated readable in the caller's AS; the three fields are read at the `struct ptrace_peeksiginfo_args` offsets (off@0, flags@8, nr@12).
    let (off, flags, nr) = unsafe {
        (core::ptr::read_unaligned(addr as *const u64),
         core::ptr::read_unaligned((addr + 8) as *const u32),
         core::ptr::read_unaligned((addr + 12) as *const i32))
    };
    let args = decide::peeksiginfo_args(off, flags, nr)?;
    let queue: Vec<sched::SigInfo> = if args.shared {
        target.thread_group.shared_sigq_snapshot()
    } else {
        target.sigq_snapshot()
    };
    let mut copied: i64 = 0;
    for i in 0..args.nr as u64 {
        let idx = match args.off.checked_add(i) { Some(v) => v, None => break };
        let Some(rec) = queue.get(idx as usize) else { break };
        let dst = data + copied as u64 * uapi::SIGINFO_BYTES;
        if write_siginfo(dst, rec).is_err() {
            if copied > 0 { return Ok(copied); }
            return Err(Errno::Efault);
        }
        copied += 1;
    }
    Ok(copied)
}

/// One queued `siginfo_t`, rendered by the shared writer so a `_sigfault`
/// record in the tracee's queue peeks out as a fault rather than as a kill
/// from a sender that never existed.
fn write_siginfo(dst: u64, rec: &sched::SigInfo) -> Result<(), Errno> {
    if crate::userbuf::validate_user_buf_writable(dst, uapi::SIGINFO_BYTES, 1).is_err() {
        return Err(Errno::Efault);
    }
    crate::signal_common::write_user_siginfo(dst, rec.signo, Some(*rec));
    Ok(())
}

/// The op the tracee's CURRENT stop presents to `PTRACE_GET_SYSCALL_INFO`.
fn stop_op(target: &Task) -> u8 {
    let code = target.ptrace_siginfo.lock().as_ref().map(|si| si.code);
    sysinfo::op_of(code, target.ptrace_eventmsg.load(Ordering::Acquire))
}

/// PTRACE_GET_SYSCALL_INFO. `addr` is the tracer's buffer SIZE and `data` the
/// buffer. Returns the size the record WOULD have needed, even when the copy
/// was truncated to fit — that is how a tracer discovers it must grow its
/// buffer.
/// # C: O(1)
pub fn get_syscall_info(target: &Task, user_size: u64, data: u64) -> Result<i64, Errno> {
    let op = stop_op(target);
    let regs = super::frame::syscall_regs(target).ok_or(Errno::Esrch)?;
    let ret_data = target.ptrace_eventmsg.load(Ordering::Acquire) as u32;
    let (bytes, actual) = sysinfo::encode(op, security::seccomp::native_audit_arch(),
                                          &regs, ret_data);
    let write = core::cmp::min(actual as u64, user_size);
    if write > 0 {
        if crate::userbuf::validate_user_buf_writable(data, write, 1).is_err() {
            return Err(Errno::Efault);
        }
        // SAFETY: `data..data+write` validated as a mapped writable range in the caller's AS; `write <= actual <= bytes.len()`, so the source range is in bounds.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), data as *mut u8, write as usize); }
    }
    Ok(actual as i64)
}

/// PTRACE_SET_SYSCALL_INFO. Installs a tracer-supplied syscall number,
/// argument list or return value into the tracee's saved entry frame.
/// # C: O(1)
pub fn set_syscall_info(target: &Task, user_size: u64, data: u64) -> Result<i64, Errno> {
    let op = stop_op(target);
    // The size rule is checked before the copy: a short record is refused
    // outright rather than read.
    if (user_size as usize) < sysinfo::SIZEOF { return Err(Errno::Einval); }
    if crate::userbuf::validate_user_buf(data, sysinfo::SIZEOF as u64, 1).is_err() {
        return Err(Errno::Efault);
    }
    let mut rec = [0u8; sysinfo::SIZEOF];
    // SAFETY: `data..data+88` validated readable in the caller's AS; the destination is a local array of exactly that length.
    unsafe { core::ptr::copy_nonoverlapping(data as *const u8, rec.as_mut_ptr(), rec.len()); }
    match sysinfo::decode_set(op, user_size as usize, &rec)? {
        sysinfo::SetRequest::Entry { nr, args, set_args } =>
            super::frame::set_syscall_entry(target, nr, &args, set_args),
        sysinfo::SetRequest::Exit { rval, is_error } =>
            super::frame::set_syscall_return(target, sysinfo::exit_return_register(rval, is_error)),
    }?;
    Ok(0)
}

/// PTRACE_SECCOMP_GET_FILTER. `addr` selects which filter of the tracee's
/// chain; `data` receives its classic-BPF instructions. Returns the filter's
/// INSTRUCTION COUNT; a null `data` asks for the count alone.
///
/// The caller gate is Linux's and is deliberately strict: CAP_SYS_ADMIN AND a
/// caller that is not itself seccomp-confined, else EACCES — a confined tracer
/// must not be able to read the filters it is confined by.
/// # C: O(filter_len)
pub fn seccomp_get_filter(cur: &Task, target: &Task, addr: u64, data: u64)
    -> Result<i64, Errno>
{
    security::seccomp::filter_read_allowed(cur.has_cap(sched::cap::SYS_ADMIN))?;
    let prog = security::seccomp::nth_filter(target, addr)?;
    if data == 0 { return Ok(prog.len() as i64); }
    let bytes = prog.len() * uapi::SOCK_FILTER_BYTES;
    if crate::userbuf::validate_user_buf_writable(data, bytes as u64, 1).is_err() {
        return Err(Errno::Efault);
    }
    for (i, insn) in prog.iter().enumerate() {
        let f = security::seccomp::SockFilter::decode(*insn);
        let p = data + (i * uapi::SOCK_FILTER_BYTES) as u64;
        // SAFETY: `data..data+len*8` validated as a mapped writable range in the caller's AS; each store stays inside that proven range at the `struct sock_filter` field offsets (code@0, jt@2, jf@3, k@4).
        unsafe {
            core::ptr::write_unaligned(p as *mut u16, f.code);
            core::ptr::write_unaligned((p + 2) as *mut u8, f.jt);
            core::ptr::write_unaligned((p + 3) as *mut u8, f.jf);
            core::ptr::write_unaligned((p + 4) as *mut u32, f.k);
        }
    }
    Ok(prog.len() as i64)
}

/// PTRACE_SECCOMP_GET_METADATA. `addr` is the tracer's buffer size; `data`
/// both carries the filter index IN and receives the record. Returns the
/// number of bytes written.
/// # C: O(N_filters)
pub fn seccomp_get_metadata(cur: &Task, target: &Task, size: u64, data: u64)
    -> Result<i64, Errno>
{
    security::seccomp::filter_read_allowed(cur.has_cap(sched::cap::SYS_ADMIN))?;
    let size = core::cmp::min(size as usize, uapi::SECCOMP_METADATA_BYTES);
    // `if (size < sizeof(kmd.filter_off)) return -EINVAL;` — the offset field
    // must at least be readable back.
    if size < 8 { return Err(Errno::Einval); }
    if crate::userbuf::validate_user_buf(data, 8, 1).is_err() { return Err(Errno::Efault); }
    // SAFETY: `data..data+8` validated readable in the caller's AS; `filter_off` is the first member of `struct seccomp_metadata`.
    let filter_off = unsafe { core::ptr::read_unaligned(data as *const u64) };
    let flags = security::seccomp::nth_filter_flags(target, filter_off)?;
    if crate::userbuf::validate_user_buf_writable(data, size as u64, 1).is_err() {
        return Err(Errno::Efault);
    }
    let mut rec = [0u8; uapi::SECCOMP_METADATA_BYTES];
    rec[0..8].copy_from_slice(&filter_off.to_ne_bytes());
    rec[8..16].copy_from_slice(&flags.to_ne_bytes());
    // SAFETY: `data..data+size` validated as a mapped writable range in the caller's AS; `size <= 16 == rec.len()`, so the source range is in bounds.
    unsafe { core::ptr::copy_nonoverlapping(rec.as_ptr(), data as *mut u8, size); }
    Ok(size as i64)
}

/// PTRACE_GET_SYSCALL_USER_DISPATCH_CONFIG. Reports the tracee's live
/// registration. The range is reported in the NORMALISED form the kernel
/// stores (an `INCLUSIVE_ON` window is kept inverted), and `mode` reports only
/// ON/OFF — which of the two ON modes armed it is not retained.
/// # C: O(1)
pub fn get_sud_config(target: &Task, size: u64, data: u64) -> Result<i64, Errno> {
    sysinfo::sud_size_ok(size)?;
    let armed = target.syscall_dispatch.armed();
    let cfg = match armed {
        Some(c) => sysinfo::SudConfig {
            mode: sysinfo::PR_SYS_DISPATCH_ON,
            selector: c.selector, offset: c.offset, len: c.len,
        },
        None => sysinfo::SudConfig { mode: sysinfo::PR_SYS_DISPATCH_OFF, ..Default::default() },
    };
    let bytes = sysinfo::sud_encode(&cfg);
    if crate::userbuf::validate_user_buf_writable(data, sysinfo::SUD_SIZEOF as u64, 1).is_err() {
        return Err(Errno::Efault);
    }
    // SAFETY: `data..data+32` validated as a mapped writable range in the caller's AS; the source is a local array of exactly that length.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), data as *mut u8, bytes.len()); }
    Ok(0)
}

/// PTRACE_SET_SYSCALL_USER_DISPATCH_CONFIG — `task_set_syscall_user_dispatch`
/// against the TRACEE, so a checkpoint/restore tool can rebuild a dispatcher
/// registration it could not have made from inside the restored process.
/// # C: O(1)
pub fn set_sud_config(target: &Task, size: u64, data: u64) -> Result<i64, Errno> {
    sysinfo::sud_size_ok(size)?;
    if crate::userbuf::validate_user_buf(data, sysinfo::SUD_SIZEOF as u64, 1).is_err() {
        return Err(Errno::Efault);
    }
    let mut buf = [0u8; sysinfo::SUD_SIZEOF];
    // SAFETY: `data..data+32` validated readable in the caller's AS; the destination is a local array of exactly that length.
    unsafe { core::ptr::copy_nonoverlapping(data as *const u8, buf.as_mut_ptr(), buf.len()); }
    let rec = sysinfo::sud_decode(&buf);
    let cfg = sched::prctl::sud::classify_set(rec.mode, rec.offset, rec.len, rec.selector)?;
    target.syscall_dispatch.install(&cfg);
    Ok(0)
}

/// PTRACE_GET_RSEQ_CONFIGURATION. `addr` is the tracer's buffer size; the
/// record is `struct ptrace_rseq_configuration`: pointer@0, size@8,
/// signature@12, flags@16, pad@20. Returns the record's full size regardless
/// of how much was copied.
/// # C: O(1)
pub fn get_rseq_configuration(target: &Task, size: u64, data: u64) -> Result<i64, Errno> {
    let mut rec = [0u8; uapi::RSEQ_CONFIGURATION_BYTES];
    rec[0..8].copy_from_slice(&target.rseq_ptr.load(Ordering::Acquire).to_ne_bytes());
    rec[8..12].copy_from_slice(&target.rseq_len.load(Ordering::Acquire).to_ne_bytes());
    rec[12..16].copy_from_slice(&target.rseq_sig.load(Ordering::Acquire).to_ne_bytes());
    let write = core::cmp::min(size as usize, rec.len());
    if write > 0 {
        if crate::userbuf::validate_user_buf_writable(data, write as u64, 1).is_err() {
            return Err(Errno::Efault);
        }
        // SAFETY: `data..data+write` validated as a mapped writable range in the caller's AS; `write <= rec.len()`, so the source range is in bounds.
        unsafe { core::ptr::copy_nonoverlapping(rec.as_ptr(), data as *mut u8, write); }
    }
    Ok(rec.len() as i64)
}
