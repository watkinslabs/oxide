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
//   101_ptrace/event.rs  PTRACE_EVENT_* policy: which event, is it enabled,
//                        what a new child inherits, EXITKILL
//   101_ptrace/sysinfo.rs `struct ptrace_syscall_info` layout + validation
//   101_ptrace/stop.rs   ptrace_notify/ptrace_event/ptrace_init_task/
//                        exit_ptrace — the live event-stop producers
//   101_ptrace/info.rs   PEEKSIGINFO, GET/SET_SYSCALL_INFO, SECCOMP_GET_*,
//                        GET_RSEQ_CONFIGURATION (kernel-only)
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

#[path = "101_ptrace/stop.rs"]   pub mod stop;
#[path = "101_ptrace/info.rs"]   pub mod info;
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
    // A request this architecture's `arch_ptrace` does not own falls through
    // to `ptrace_request`'s EIO default — checked here so the arm below cannot
    // answer a request the running arch has no ABI struct for.
    if decide::unsupported_on_arch(request, frame::ARCH) { return Err(Errno::Eio); }

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
        uapi::PEEKSIGINFO => info::peeksiginfo(&target, addr, data),
        uapi::GET_SYSCALL_INFO => info::get_syscall_info(&target, addr, data),
        uapi::SET_SYSCALL_INFO => info::set_syscall_info(&target, addr, data),
        uapi::SECCOMP_GET_FILTER   => info::seccomp_get_filter(&cur, &target, addr, data),
        uapi::SECCOMP_GET_METADATA => info::seccomp_get_metadata(&cur, &target, addr, data),
        uapi::GET_RSEQ_CONFIGURATION => info::get_rseq_configuration(&target, addr, data),
        uapi::GET_SYSCALL_USER_DISPATCH_CONFIG => info::get_sud_config(&target, addr, data),
        uapi::SET_SYSCALL_USER_DISPATCH_CONFIG => info::set_sud_config(&target, addr, data),
        uapi::CONT | uapi::SYSCALL | uapi::SINGLESTEP =>
            resume(&target, request, data).map(|_| 0),
        uapi::DETACH => detach(&target, data).map(|_| 0),
        uapi::KILL   => { kill(&target); Ok(0) }
        // `ptrace_request` seeds -EIO and its default arm leaves it there.
        // PTRACE_GETFDPIC is CONFIG_BINFMT_ELF_FDPIC-only (no-MMU targets) and
        // is absent from the switch on every arch this port builds for, so EIO
        // is the answer Linux itself gives.
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
    // `security_ptrace_traceme(current->parent)` — Yama's two highest scopes
    // refuse even a volunteered trace.
    if let Some(p) = sched::live::registry::lookup(parent) { perm::may_traceme(&p)?; }
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
        let suspended = cur.ptrace_options.load(Ordering::Acquire) & uapi::O_SUSPEND_SECCOMP != 0;
        decide::check_seize_full(addr, data, cur.has_cap(sched::cap::SYS_ADMIN), seccomp, suspended)?
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
        sched::live::send_sig_priv_group(target, Signum::Sigstop as u32);
    }
    Ok(())
}

/// PTRACE_CONT / PTRACE_SYSCALL / PTRACE_SINGLESTEP.
///
/// `data` does NOT queue a signal. Linux's `ptrace_resume` publishes it in
/// `child->exit_code` and wakes the tracee; the tracee reads it back out of
/// `ptrace_stop` and — depending on which kind of stop it was in — DELIVERS it
/// in place of the signal it reported (a signal-delivery stop), or re-posts it
/// (a syscall stop's `ptrace_report_syscall` does `send_sig(signr, current,
/// 1)`), or drops it (an event stop, whose `ptrace_event` discards the return).
/// Queuing it here instead made every value an EXTRA signal on top of the one
/// the tracee reported, so a tracer could never suppress or replace a signal —
/// only add to it.
fn resume(target: &Arc<sched::Task>, request: u64, data: u64) -> Result<(), Errno> {
    // Linux `ptrace_resume` rejects an out-of-range signal with EIO before
    // touching any state.
    if !decide::valid_signal(data) { return Err(Errno::Eio); }
    target.singlestep.store(u32::from(request == uapi::SINGLESTEP), Ordering::Release);
    target.ptrace_syscall_armed.store(request == uapi::SYSCALL, Ordering::Release);
    // `child->exit_code = data` — the cell `stop_code` already is. The
    // tracee's `last_siginfo` is NOT cleared here: `PTRACE_SETSIGINFO` may
    // have rewritten the record this very resume is about to deliver, and the
    // tracee clears it itself once it has read it (Linux `ptrace_stop`'s tail).
    target.stop_code.store(data as u32, Ordering::Release);
    // The tracer's own resume clears the whole trap latch, `JOBCTL_LISTENING`
    // included: a `PTRACE_LISTEN` is ended by the next resume, not carried
    // into it, or the tracee would re-trap instead of running.
    clear_trap_latch(target);
    sched::live::registry::wake_if_stopped(target, sched::jobctl::WakeKind::PtraceResume);
    Ok(())
}

/// Clear `JOBCTL_PENDING_MASK | JOBCTL_LISTENING` on a resumed tracee.
/// # C: O(1)
fn clear_trap_latch(target: &sched::Task) {
    let jc = target.jobctl.load(Ordering::Acquire);
    target.jobctl.store(sched::jobctl::resume_clears(jc), Ordering::Release);
}

/// PTRACE_DETACH. Same `valid_signal` gate as resume, and the same
/// publish-then-wake handoff: `ptrace_detach` sets `child->exit_code = data`
/// before `__ptrace_detach`, so a detach can deliver a parting signal through
/// the stop the tracee is sitting in.
fn detach(target: &Arc<sched::Task>, data: u64) -> Result<(), Errno> {
    if !decide::valid_signal(data) { return Err(Errno::Eio); }
    target.stop_code.store(data as u32, Ordering::Release);
    target.traced_by.store(0, Ordering::Release);
    target.ptrace_seized.store(false, Ordering::Release);
    target.ptrace_options.store(0, Ordering::Release);
    target.ptrace_syscall_armed.store(false, Ordering::Release);
    target.singlestep.store(0, Ordering::Release);
    // Drop the ATTACH-induced SIGSTOP unless the tracer asked for a signal.
    if data == 0 {
        target.sigpending.fetch_and(!Signum::Sigstop.bit(), Ordering::Release);
    }
    clear_trap_latch(target);
    sched::live::registry::wake_if_stopped(target, sched::jobctl::WakeKind::PtraceResume);
    Ok(())
}

/// PTRACE_KILL — Linux sends SIGKILL and returns 0 regardless of stop state.
fn kill(target: &Arc<sched::Task>) {
    sched::live::send_sig_priv_group(target, Signum::Sigkill as u32);
}
