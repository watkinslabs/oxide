// 101 ptrace — one syscall, one file (`53§0`). ABI shim + request routing
// only; every decision lives in a hosted-tested sibling:
//
//   101_ptrace/uapi.rs   request/option/event/note numbers
//   101_ptrace/decide.rs scalar validation (options, signals, regsets, user area)
//   101_ptrace/perm.rs   __ptrace_may_access / ptrace_attach / ptrace_check_attach
//   101_ptrace/regs.rs   saved-frame <-> user_regs_struct / user_pt_regs
//   101_ptrace/frame.rs  foreign-task frame access (kernel-only)
//   101_ptrace/mem.rs    PEEK/POKE text, data and user area (kernel-only)
//   101_ptrace/regset.rs GETREGS/SETREGS/GETREGSET/SETREGSET (kernel-only)
//   101_ptrace/sig.rs    options, siginfo, sigmask, INTERRUPT, LISTEN (kernel-only)
//
// Order of checks follows `SYSCALL_DEFINE4(ptrace)`: TRACEME first (no
// target), then pid lookup (ESRCH), then ATTACH/SEIZE (their own gate), then
// `ptrace_check_attach` (ESRCH) for everything else. Unknown requests return
// **EIO** — `ptrace_request` seeds `ret = -EIO` and its default arm leaves it.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use sched::Signum;
use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::s101_ptrace_uapi as uapi;
use crate::s101_ptrace_decide as decide;
use crate::s101_ptrace_perm as perm;

#[path = "101_ptrace/frame.rs"]  pub mod frame;
#[path = "101_ptrace/mem.rs"]    pub mod mem;
#[path = "101_ptrace/regset.rs"] pub mod regset;
#[path = "101_ptrace/sig.rs"]    pub mod sig;

/// `sys_ptrace(request, pid, addr, data)` — slot 101.
/// # C: O(N_tasks) for the pid lookup; O(1) or O(regset bytes) thereafter.
pub fn sys_ptrace(args: &SyscallArgs) -> i64 {
    match dispatch(args) {
        Ok(v)  => v,
        Err(e) => -(e.as_i32() as i64),
    }
}

fn dispatch(args: &SyscallArgs) -> Result<i64, Errno> {
    let request = args.a0;
    let pid     = args.a1 as u32;
    let addr    = args.a2;
    let data    = args.a3;

    let cur = sched::live::current().ok_or(Errno::Esrch)?;
    if request == uapi::TRACEME { return traceme(&cur).map(|_| 0); }

    let target = sched::live::registry::resolve_user_pid(pid).ok_or(Errno::Esrch)?;
    if request == uapi::ATTACH || request == uapi::SEIZE {
        return attach(&cur, &target, request, addr, data).map(|_| 0);
    }
    perm::check_attach(&cur, &target, !decide::ignores_stop_state(request))?;

    match request {
        uapi::PEEKTEXT | uapi::PEEKDATA => mem::peek(&target, addr, data).map(|_| 0),
        uapi::POKETEXT | uapi::POKEDATA => mem::poke(&target, addr, data).map(|_| 0),
        uapi::PEEKUSER => mem::peek_user(&target, addr, data).map(|_| 0),
        uapi::POKEUSER => mem::poke_user(&target, addr, data).map(|_| 0),
        uapi::GETREGS  => regset::getregs(&target, data).map(|_| 0),
        uapi::SETREGS  => regset::setregs(&target, data).map(|_| 0),
        uapi::GETFPREGS => mem::fpregs_out(&target, data, fpregs_bytes()).map(|_| 0),
        uapi::SETFPREGS => mem::fpregs_in(&target, data, fpregs_bytes()).map(|_| 0),
        uapi::GETREGSET => regset::regset(&target, addr, data, false).map(|_| 0),
        uapi::SETREGSET => regset::regset(&target, addr, data, true).map(|_| 0),
        uapi::SETOPTIONS  => sig::setoptions(&cur, &target, data).map(|_| 0),
        uapi::GETEVENTMSG => sig::geteventmsg(&target, data).map(|_| 0),
        uapi::GETSIGINFO  => sig::getsiginfo(&target, data).map(|_| 0),
        uapi::SETSIGINFO  => sig::setsiginfo(&target, data).map(|_| 0),
        uapi::GETSIGMASK  => sig::getsigmask(&target, addr, data).map(|_| 0),
        uapi::SETSIGMASK  => sig::setsigmask(&target, addr, data).map(|_| 0),
        uapi::INTERRUPT   => sig::interrupt(&target).map(|_| 0),
        uapi::LISTEN      => sig::listen(&target).map(|_| 0),
        uapi::CONT | uapi::SYSCALL | uapi::SINGLESTEP =>
            resume(&target, request, data).map(|_| 0),
        uapi::DETACH => detach(&target, data).map(|_| 0),
        uapi::KILL   => { kill(&target); Ok(0) }
        // `ptrace_request` seeds -EIO and its default arm leaves it there;
        // PTRACE_PEEKSIGINFO and the seccomp/rseq/syscall-info requests are
        // not implemented and land here honestly rather than faking success.
        _ => Err(Errno::Eio),
    }
}

#[cfg(target_arch = "x86_64")]
fn fpregs_bytes() -> usize { uapi::X86_USER_I387_BYTES }
#[cfg(target_arch = "aarch64")]
fn fpregs_bytes() -> usize { uapi::ARM64_USER_FPSIMD_BYTES }

/// PTRACE_TRACEME. Linux `ptrace_traceme` refuses when the caller is already
/// traced (EPERM) — re-registering would silently reparent the ptrace link.
fn traceme(cur: &sched::Task) -> Result<(), Errno> {
    if cur.traced_by.load(Ordering::Acquire) != 0 { return Err(Errno::Eperm); }
    let parent = cur.parent_tid.load(Ordering::Acquire);
    if parent == 0 { return Err(Errno::Eperm); }
    cur.traced_by.store(parent, Ordering::Release);
    cur.ptrace_seized.store(false, Ordering::Release);
    Ok(())
}

/// PTRACE_ATTACH / PTRACE_SEIZE.
fn attach(cur: &sched::Task, target: &Arc<sched::Task>, request: u64, addr: u64, data: u64)
    -> Result<(), Errno>
{
    let seize = request == uapi::SEIZE;
    // SEIZE validates its arguments BEFORE the permission gate (Linux
    // `ptrace_attach` runs the EIO checks first), so a bad option word is
    // reported as EIO even to a caller that could not have attached.
    let opts = if seize {
        let seccomp = security::seccomp::mode_of_current() != 0;
        decide::check_seize(addr, data, cur.has_cap(sched::cap::SYS_ADMIN), seccomp)?
    } else { 0 };
    // A task with no user address space is Linux's PF_KTHREAD.
    let is_kthread = target.clone_mm().is_none();
    let exiting = target.state() == sched::TaskState::Zombie;
    perm::may_attach(cur, target, is_kthread, exiting)?;
    target.traced_by.store(cur.tid, Ordering::Release);
    target.ptrace_seized.store(seize, Ordering::Release);
    target.ptrace_options.store(opts, Ordering::Release);
    if !seize {
        // ATTACH posts SIGSTOP so the tracee stops at its next signal-delivery
        // point; SEIZE attaches without any stop (the tracer uses INTERRUPT).
        target.sigpending.fetch_or(Signum::Sigstop.bit(), Ordering::Release);
        sched::live::signal_wake_up(target);
    }
    Ok(())
}

/// PTRACE_CONT / PTRACE_SYSCALL / PTRACE_SINGLESTEP.
fn resume(target: &Arc<sched::Task>, request: u64, data: u64) -> Result<(), Errno> {
    // Linux `ptrace_resume` rejects an out-of-range signal with EIO before
    // touching any state.
    if !decide::valid_signal(data) { return Err(Errno::Eio); }
    let sig = data as u32;
    if sig != 0 {
        target.sigpending.fetch_or(1u64 << (sig - 1), Ordering::Release);
        sched::live::signal_wake_up(target);
    }
    target.singlestep.store(u32::from(request == uapi::SINGLESTEP), Ordering::Release);
    target.ptrace_syscall_armed.store(request == uapi::SYSCALL, Ordering::Release);
    *target.ptrace_siginfo.lock() = None;
    sched::live::registry::wake_if_stopped(target);
    Ok(())
}

/// PTRACE_DETACH. Same `valid_signal` gate as resume.
fn detach(target: &Arc<sched::Task>, data: u64) -> Result<(), Errno> {
    if !decide::valid_signal(data) { return Err(Errno::Eio); }
    target.traced_by.store(0, Ordering::Release);
    target.ptrace_seized.store(false, Ordering::Release);
    target.ptrace_options.store(0, Ordering::Release);
    target.ptrace_syscall_armed.store(false, Ordering::Release);
    target.singlestep.store(0, Ordering::Release);
    *target.ptrace_siginfo.lock() = None;
    // Drop the ATTACH-induced SIGSTOP unless the tracer asked for a signal.
    if data == 0 {
        target.sigpending.fetch_and(!Signum::Sigstop.bit(), Ordering::Release);
    } else {
        target.sigpending.fetch_or(1u64 << (data - 1), Ordering::Release);
    }
    sched::live::registry::wake_if_stopped(target);
    Ok(())
}

/// PTRACE_KILL — Linux sends SIGKILL and returns 0 regardless of stop state.
fn kill(target: &Arc<sched::Task>) {
    target.sigpending.fetch_or(Signum::Sigkill.bit(), Ordering::Release);
    sched::live::signal_wake_up(target);
}
