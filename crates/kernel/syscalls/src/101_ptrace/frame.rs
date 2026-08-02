// Foreign-task saved-entry-frame access for ptrace GETREGS/SETREGS/
// GETREGSET/SETREGSET/PEEKUSER/POKEUSER. The tracee is verified
// ptrace-stopped by `perm::check_attach` before any of this runs, so its
// entry frame is quiescent.
//
// The frame's address and size are DERIVED from the struct the entry asm
// pushes — `PtRegs` on x86_64, `SvcFrame` on aarch64 — so this file states no
// offset of its own. A hand-maintained copy is what made `PTRACE_GETREGS`
// report `rcx` as `rip` and `r11` as `orig_rax` after the x86_64 frame grew
// from 16 to 22 quadwords.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;
use sched::Task;
use syscall::errno::Errno;

#[cfg(target_arch = "x86_64")]
pub use crate::s101_ptrace_regs::x86::Frame;
#[cfg(target_arch = "x86_64")]
pub const REGS_N: usize = crate::s101_ptrace_regs::x86::N;

#[cfg(target_arch = "aarch64")]
pub use crate::s101_ptrace_regs::arm64::Frame;
#[cfg(target_arch = "aarch64")]
pub const REGS_N: usize = crate::s101_ptrace_regs::arm64::N;

/// Bytes the entry path reserves for the saved frame — its own size, so the
/// base can never address the middle of it.
pub const FRAME_BYTES: u64 = core::mem::size_of::<Frame>() as u64;

/// This build's regset view.
#[cfg(target_arch = "x86_64")]
pub const ARCH: crate::s101_ptrace_decide::Arch = crate::s101_ptrace_decide::Arch::X86_64;
#[cfg(target_arch = "aarch64")]
pub const ARCH: crate::s101_ptrace_decide::Arch = crate::s101_ptrace_decide::Arch::Aarch64;

fn base(t: &Task) -> Option<*mut Frame> {
    // aarch64 records the exact frame pointer at syscall dispatch entry
    // (`dispatch/core.rs`), which is also where a fault handler re-points it;
    // prefer it over deriving the address from the stack top.
    #[cfg(target_arch = "aarch64")]
    {
        let p = t.svc_frame.load(Ordering::Acquire);
        if p != 0 { return Some(p as *mut Frame); }
    }
    let top = t.kernel_stack.load(Ordering::Acquire);
    if top.is_null() { return None; }
    Some((top as u64 - FRAME_BYTES) as *mut Frame)
}

/// Snapshot the tracee's saved entry frame.
/// # C: O(1) — fixed-size copy.
pub fn read(t: &Task) -> Option<Frame> {
    let p = base(t)?;
    // SAFETY: `p` is the tracee's own kernel stack minus the entry-frame size; the tracee is ptrace-stopped (checked by perm::check_attach) so no CPU is writing the frame; the read is one aligned struct inside the stack allocation.
    Some(unsafe { core::ptr::read_volatile(p) })
}

/// Write the tracee's saved entry frame back.
/// # C: O(1) — fixed-size copy.
pub fn write(t: &Task, f: &Frame) -> Option<()> {
    let p = base(t)?;
    // SAFETY: same frame the tracee will resume from; it is ptrace-stopped, so the scheduler cannot re-enter it while we write; the store is one aligned struct inside the stack allocation.
    unsafe { core::ptr::write_volatile(p, *f); }
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
        // The frame's `rax` slot holds the syscall number for the whole
        // dispatch (Linux `orig_ax`); `r10` substitutes for `rcx`, which the
        // `syscall` instruction clobbers with the user return address.
        Some(Regs {
            nr: f.rax,
            args: [f.rdi, f.rsi, f.rdx, f.r10, f.r8, f.r9],
            ip: f.rip, sp: f.rsp, rval,
        })
    }
    #[cfg(target_arch = "aarch64")]
    {
        // The generic arm64 ABI passes the syscall number in x8 and the
        // six arguments in x0..x5.
        Some(Regs {
            nr: f.gp[ARM_NR_REG],
            args: [f.gp[0], f.gp[1], f.gp[2], f.gp[3], f.gp[4], f.gp[5]],
            ip: f.elr_el1, sp: f.sp_el0, rval,
        })
    }
}

/// arm64 syscall-number register (`x8`) within the frame's `x0..x17` block.
#[cfg(target_arch = "aarch64")]
const ARM_NR_REG: usize = 8;

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
        f.rax = nr as u64;
        if set_args {
            f.rdi = args[0]; f.rsi = args[1]; f.rdx = args[2];
            f.r10 = args[3]; f.r8  = args[4]; f.r9  = args[5];
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        f.gp[ARM_NR_REG] = nr as u64;
        if set_args { f.gp[..args.len()].copy_from_slice(args); }
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
        f.retval = rval as u64;
        write(t, &f).ok_or(Errno::Esrch)?;
    }
    Ok(())
}

/// Segment state the entry frame does not carry. `cs`/`ss` are not here — the
/// frame holds the pair the entry actually pushed. `fs_base` and `gs_base`
/// come from the tracee's saved `ArchCtx`, the same fields
/// `arch_prctl(ARCH_SET_FS/ARCH_SET_GS)` mirrors and the context switch
/// reloads. The four data selectors are unused by this port's code model.
#[cfg(target_arch = "x86_64")]
fn seg_state(t: &Task) -> crate::s101_ptrace_regs::x86::SegState {
    // SAFETY: the tracee is ptrace-stopped, so no CPU is running its context switch; `arch_ctx_ptr` returns its own context buffer, whose fs_base/gs_base fields the ctxsw keeps in sync with IA32_FS_BASE / IA32_KERNEL_GS_BASE.
    let (fs_base, gs_base) = unsafe {
        let p = t.arch_ctx_ptr::<hal_x86_64::ContextX86_64>();
        ((*p).fs_base, (*p).gs_base)
    };
    crate::s101_ptrace_regs::x86::SegState {
        ds: 0, es: 0, fs: 0, gs: 0,
        fs_base, gs_base,
    }
}
