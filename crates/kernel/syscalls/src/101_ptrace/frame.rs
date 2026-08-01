// Foreign-task saved-entry-frame access for ptrace GETREGS/SETREGS/
// GETREGSET/SETREGSET/PEEKUSER/POKEUSER. The tracee is verified
// ptrace-stopped by `perm::check_attach` before any of this runs, so its
// entry frame is quiescent.
//
// Layout constants are pinned against the entry asm:
//   x86_64  — `oxide_syscall_entry` pushes 16 quadwords, base = top - 0x80.
//   aarch64 — the EL0-sync save block does `sub sp, sp, #288`, so the
//             288-byte `SvcFrame` base = top - 0x120. (The previous 0xD0
//             here addressed the *middle* of the frame: reads returned
//             x19..x28 as x0..x17 and an 18-slot write ran 0x40 bytes past
//             the stack top.)

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;
use sched::Task;
use syscall::errno::Errno;

#[cfg(target_arch = "x86_64")]
pub use crate::s101_ptrace_regs::x86::FRAME_N;
#[cfg(target_arch = "x86_64")]
pub const FRAME_OFF: u64 = 0x80;
#[cfg(target_arch = "x86_64")]
pub const REGS_N: usize = crate::s101_ptrace_regs::x86::N;

#[cfg(target_arch = "aarch64")]
pub use crate::s101_ptrace_regs::arm64::FRAME_N;
#[cfg(target_arch = "aarch64")]
pub const FRAME_OFF: u64 = 0x120;
#[cfg(target_arch = "aarch64")]
pub const REGS_N: usize = crate::s101_ptrace_regs::arm64::N;

/// This build's regset view.
#[cfg(target_arch = "x86_64")]
pub const ARCH: crate::s101_ptrace_decide::Arch = crate::s101_ptrace_decide::Arch::X86_64;
#[cfg(target_arch = "aarch64")]
pub const ARCH: crate::s101_ptrace_decide::Arch = crate::s101_ptrace_decide::Arch::Aarch64;

fn base(t: &Task) -> Option<*mut u64> {
    // aarch64 records the exact frame pointer at syscall dispatch entry
    // (`dispatch/core.rs`), which is also where a fault handler re-points it;
    // prefer it over deriving the address from the stack top.
    #[cfg(target_arch = "aarch64")]
    {
        let p = t.svc_frame.load(Ordering::Acquire);
        if p != 0 { return Some(p as *mut u64); }
    }
    let top = t.kernel_stack.load(Ordering::Acquire);
    if top.is_null() { return None; }
    Some((top as u64 - FRAME_OFF) as *mut u64)
}

/// Snapshot the tracee's saved entry frame.
/// # C: O(1) — fixed-size copy.
pub fn read(t: &Task) -> Option<[u64; FRAME_N]> {
    let p = base(t)?;
    let mut f = [0u64; FRAME_N];
    // SAFETY: `p` is the tracee's own kernel stack minus the entry-frame size; the tracee is ptrace-stopped (checked by perm::check_attach) so no CPU is writing the frame; reads are aligned quadwords inside the stack allocation.
    unsafe { for i in 0..FRAME_N { f[i] = core::ptr::read_volatile(p.add(i)); } }
    Some(f)
}

/// Write the tracee's saved entry frame back.
/// # C: O(1) — fixed-size copy.
pub fn write(t: &Task, f: &[u64; FRAME_N]) -> Option<()> {
    let p = base(t)?;
    // SAFETY: same frame the tracee will resume from; it is ptrace-stopped, so the scheduler cannot re-enter it while we write; stores are aligned quadwords inside the stack allocation.
    unsafe { for i in 0..FRAME_N { core::ptr::write_volatile(p.add(i), f[i]); } }
    Some(())
}

/// Materialise the tracee's ABI register struct.
/// # C: O(1)
pub fn user_regs(t: &Task) -> Option<[u64; REGS_N]> {
    let f = read(t)?;
    let rv = t.ptrace_stop_rax.load(Ordering::Acquire);
    #[cfg(target_arch = "x86_64")]
    {
        Some(crate::s101_ptrace_regs::x86::to_user_regs(&f, rv, &seg_state(t)))
    }
    #[cfg(target_arch = "aarch64")]
    {
        Some(crate::s101_ptrace_regs::arm64::to_user_pt_regs(&f, rv))
    }
}

/// Install a tracer-supplied ABI register struct.
/// # C: O(1)
pub fn set_user_regs(t: &Task, u: &[u64; REGS_N]) -> Result<(), Errno> {
    let mut f = match read(t) { Some(f) => f, None => return Err(Errno::Esrch) };
    #[cfg(target_arch = "x86_64")]
    {
        let mut seg = seg_state(t);
        let rax = crate::s101_ptrace_regs::x86::from_user_regs(u, &mut f, &mut seg, ::hal::USER_VA_END)?;
        // SAFETY: the tracee is ptrace-stopped, so its ArchCtx is not being switched; `arch_ctx_ptr` returns its own context buffer, and fs_base/gs_base are the fields the ctxsw reloads into IA32_FS_BASE / IA32_KERNEL_GS_BASE.
        unsafe {
            let p = t.arch_ctx_ptr::<hal_x86_64::ContextX86_64>();
            (*p).fs_base = seg.fs_base;
            (*p).gs_base = seg.gs_base;
        }
        t.ptrace_stop_rax.store(rax, Ordering::Release);
    }
    #[cfg(target_arch = "aarch64")]
    {
        crate::s101_ptrace_regs::arm64::from_user_pt_regs(u, &mut f);
        t.ptrace_stop_rax.store(u[0], Ordering::Release);
    }
    match write(t, &f) { Some(()) => Ok(()), None => Err(Errno::Esrch) }
}

/// The syscall-stop register view `PTRACE_GET_SYSCALL_INFO` reports:
/// `syscall_get_nr`, `syscall_get_arguments`, `instruction_pointer`,
/// `user_stack_pointer` and the ABI return register.
/// # C: O(1)
pub fn syscall_regs(t: &Task) -> Option<crate::s101_ptrace_sysinfo::Regs> {
    use crate::s101_ptrace_sysinfo::Regs;
    let f = read(t)?;
    let rval = t.ptrace_stop_rax.load(Ordering::Acquire) as i64;
    #[cfg(target_arch = "x86_64")]
    {
        use crate::s101_ptrace_regs::x86::*;
        Some(Regs {
            nr: f[F_ORIG_RAX],
            args: [f[F_RDI], f[F_RSI], f[F_RDX], f[F_R10], f[F_R8], f[F_R9]],
            ip: f[F_RIP], sp: f[F_RSP], rval,
        })
    }
    #[cfg(target_arch = "aarch64")]
    {
        use crate::s101_ptrace_regs::arm64::*;
        Some(Regs {
            // The generic arm64 ABI passes the syscall number in x8 and the
            // six arguments in x0..x5.
            nr: f[F_X0 + 8],
            args: [f[F_X0], f[F_X0 + 1], f[F_X0 + 2], f[F_X0 + 3], f[F_X0 + 4], f[F_X0 + 5]],
            ip: f[F_ELR], sp: f[F_SP_EL0], rval,
        })
    }
}

/// `syscall_set_nr` + `syscall_set_arguments`. `set_args` is false when the
/// tracer cancelled the call with `nr == -1`, where writing the argument
/// registers would clobber the return register on an ABI that shares them.
/// # C: O(1)
pub fn set_syscall_entry(t: &Task, nr: i64, args: &[u64; 6], set_args: bool)
    -> Result<(), Errno>
{
    let mut f = read(t).ok_or(Errno::Esrch)?;
    #[cfg(target_arch = "x86_64")]
    {
        use crate::s101_ptrace_regs::x86::*;
        f[F_ORIG_RAX] = nr as u64;
        if set_args {
            f[F_RDI] = args[0]; f[F_RSI] = args[1]; f[F_RDX] = args[2];
            f[F_R10] = args[3]; f[F_R8]  = args[4]; f[F_R9]  = args[5];
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        use crate::s101_ptrace_regs::arm64::*;
        f[F_X0 + 8] = nr as u64;
        if set_args { for i in 0..6 { f[F_X0 + i] = args[i]; } }
    }
    write(t, &f).ok_or(Errno::Esrch)
}

/// `syscall_set_return_value`. The value lands in the same slot
/// `PTRACE_GETREGS` reports, which is the task-side `ptrace_stop_rax` cell
/// rather than the frame word holding the syscall number.
/// # C: O(1)
pub fn set_syscall_return(t: &Task, rval: i64) -> Result<(), Errno> {
    t.ptrace_stop_rax.store(rval as u64, Ordering::Release);
    #[cfg(target_arch = "aarch64")]
    {
        let mut f = read(t).ok_or(Errno::Esrch)?;
        f[crate::s101_ptrace_regs::arm64::F_RETVAL] = rval as u64;
        write(t, &f).ok_or(Errno::Esrch)?;
    }
    Ok(())
}

/// Segment state the entry frame does not carry. `cs`/`ss` are this port's
/// fixed user selectors; `fs_base` and `gs_base` come from the tracee's saved
/// `ArchCtx`, the same fields `arch_prctl(ARCH_SET_FS/ARCH_SET_GS)` mirrors
/// and the context switch reloads.
#[cfg(target_arch = "x86_64")]
fn seg_state(t: &Task) -> crate::s101_ptrace_regs::x86::SegState {
    // SAFETY: the tracee is ptrace-stopped, so no CPU is running its context switch; `arch_ctx_ptr` returns its own context buffer, whose fs_base/gs_base fields the ctxsw keeps in sync with IA32_FS_BASE / IA32_KERNEL_GS_BASE.
    let (fs_base, gs_base) = unsafe {
        let p = t.arch_ctx_ptr::<hal_x86_64::ContextX86_64>();
        ((*p).fs_base, (*p).gs_base)
    };
    crate::s101_ptrace_regs::x86::SegState {
        cs: hal_x86_64::USER_CS as u64,
        ss: hal_x86_64::USER_DS as u64,
        ds: 0, es: 0, fs: 0, gs: 0,
        fs_base, gs_base,
    }
}
