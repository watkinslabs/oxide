// PTRACE_PEEKTEXT/PEEKDATA/POKETEXT/POKEDATA/PEEKUSER/POKEUSER.
//
// Return convention (the classic ptrace trap): Linux
// `generic_ptrace_peekdata` does `put_user(tmp, data)` and returns **0** —
// the peeked word travels through the `data` pointer, not the syscall return
// value. glibc's `ptrace()` wrapper relies on exactly that: it passes
// `&result` as `data`, then returns `result`. Returning the word as the
// syscall rv (what this file used to do) makes every word with bit 63..
// bit 9 set look like a negative errno to the raw syscall wrapper, so
// peeking a stack address or a pointer failed with a bogus errno.
//
// Failure convention: a foreign-memory access that comes up short is
// **EIO**, not EFAULT (`generic_ptrace_peekdata`/`pokedata`). EFAULT is
// reserved for the `put_user` into the tracer's own buffer.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;
use sched::Task;
use syscall::errno::Errno;
use crate::s101_ptrace_decide as decide;
use crate::s101_ptrace_decide::UserArea;

const WORD: usize = 8;

/// PTRACE_PEEKTEXT / PTRACE_PEEKDATA.
/// # C: O(1) — one 8-byte foreign-AS read.
pub fn peek(target: &Task, addr: u64, data: u64) -> Result<(), Errno> {
    let mm = target.clone_mm().ok_or(Errno::Esrch)?;
    let mut buf = [0u8; WORD];
    // SAFETY: the mm Arc pins the tracee's page tables against a concurrent exit/execve replacement; HHDM is initialised before any user task runs; read_foreign_user walks that root and reports the byte count it actually copied.
    let n = unsafe { pmm::user_as::read_foreign_user(mm.root_pa(), addr, &mut buf[..]) };
    if n != WORD { return Err(Errno::Eio); }
    put_word(data, u64::from_le_bytes(buf))
}

/// PTRACE_POKETEXT / PTRACE_POKEDATA.
/// # C: O(1) — one 8-byte foreign-AS write.
pub fn poke(target: &Task, addr: u64, data: u64) -> Result<(), Errno> {
    let mm = target.clone_mm().ok_or(Errno::Esrch)?;
    let buf = data.to_le_bytes();
    // SAFETY: the mm Arc pins the tracee's page tables; write_foreign_user verifies leaf writability per chunk before storing and reports the byte count written.
    let n = unsafe { pmm::user_as::write_foreign_user(mm.root_pa(), addr, &buf[..]) };
    if n != WORD { return Err(Errno::Eio); }
    Ok(())
}

/// PTRACE_PEEKUSER: a quadword of the tracee's `struct user`.
/// # C: O(1)
pub fn peek_user(target: &Task, addr: u64, data: u64) -> Result<(), Errno> {
    let word = match decide::user_area(addr)? {
        UserArea::Reg(i) => {
            let u = super::frame::user_regs(target).ok_or(Errno::Esrch)?;
            // arm64 exposes fewer quadwords through `struct user` than x86's
            // 27; anything past the end reads as the zero Linux also returns.
            if i < super::frame::REGS_N { u[i] } else { 0 }
        }
        // No hardware debug registers are wired on this port, so DR0..DR7
        // read as zero — the same value Linux reports for a task that never
        // armed one.
        UserArea::DebugReg(_) | UserArea::Padding => 0,
    };
    put_word(data, word)
}

/// PTRACE_POKEUSER: install a quadword into the tracee's `struct user`.
/// # C: O(1)
pub fn poke_user(target: &Task, addr: u64, data: u64) -> Result<(), Errno> {
    match decide::user_area(addr)? {
        UserArea::Reg(i) => {
            if i >= super::frame::REGS_N { return Err(Errno::Eio); }
            let mut u = super::frame::user_regs(target).ok_or(Errno::Esrch)?;
            u[i] = data;
            super::frame::set_user_regs(target, &u)
        }
        // Writing a debug register we do not implement must not report
        // success — a tracer would then believe a hardware watchpoint is
        // armed. Linux's own arm is `ptrace_set_debugreg`, which errors on
        // an unsupported request too.
        UserArea::DebugReg(_) => Err(Errno::Eio),
        // Padding inside `struct user` is writable-but-ignored on Linux.
        UserArea::Padding => Ok(()),
    }
}

/// `put_user(word, data)` into the tracer's own address space.
fn put_word(data: u64, word: u64) -> Result<(), Errno> {
    if crate::userbuf::validate_user_buf_writable(data, WORD as u64, 1).is_err() {
        return Err(Errno::Efault);
    }
    // SAFETY: `data..data+8` was accepted by validate_user_buf_writable, so it is a mapped writable range in the *caller's* live address space; CPL=0 unaligned store (Linux put_user accepts unaligned too).
    unsafe { core::ptr::write_unaligned(data as *mut u64, word); }
    Ok(())
}

/// FPU snapshot copy-out for PTRACE_GETFPREGS / GETREGSET(NT_PRFPREG).
/// # C: O(n) — 512/528-byte copy.
pub fn fpregs_out(target: &Task, data: u64, n: usize) -> Result<(), Errno> {
    if crate::userbuf::validate_user_buf_writable(data, n as u64, 1).is_err() {
        return Err(Errno::Efault);
    }
    // SAFETY: the tracee is ptrace-stopped, so its fpu_state cannot be torn by a concurrent ctxsw fpu_save; the destination range was validated writable in the caller's AS; both sides are byte copies of `n` bytes inside their allocations.
    unsafe {
        let src = (*target.fpu_state.get()).as_ptr();
        for i in 0..n {
            core::ptr::write_volatile((data + i as u64) as *mut u8, core::ptr::read(src.add(i)));
        }
    }
    Ok(())
}

/// FPU snapshot copy-in for PTRACE_SETFPREGS / SETREGSET(NT_PRFPREG).
/// # C: O(n) — 512/528-byte copy.
pub fn fpregs_in(target: &Task, data: u64, n: usize) -> Result<(), Errno> {
    if crate::userbuf::validate_user_buf(data, n as u64, 1).is_err() {
        return Err(Errno::Efault);
    }
    // SAFETY: the tracee is ptrace-stopped, so the picker cannot re-enter it and the fpu_state single-mutator rule (`13§5`) holds; the source range was validated readable in the caller's AS.
    unsafe {
        let dst = (*target.fpu_state.get()).as_mut_ptr();
        for i in 0..n {
            core::ptr::write(dst.add(i), core::ptr::read_volatile((data + i as u64) as *const u8));
        }
    }
    target.ptrace_fpu_dirty.store(true, Ordering::Release);
    Ok(())
}
