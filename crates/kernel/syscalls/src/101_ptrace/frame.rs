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
        // No user GS base exists on this port (arch_prctl has no ARCH_SET_GS),
        // so a non-zero request cannot be honoured; refusing is EIO rather
        // than a silent drop.
        if seg.gs_base != 0 { return Err(Errno::Eio); }
        // SAFETY: the tracee is ptrace-stopped, so its ArchCtx is not being switched; `arch_ctx_ptr` returns its own 64-byte context buffer and `fs_base` is the field the ctxsw reloads into IA32_FS_BASE.
        unsafe { (*t.arch_ctx_ptr::<hal_x86_64::ContextX86_64>()).fs_base = seg.fs_base; }
        t.ptrace_stop_rax.store(rax, Ordering::Release);
    }
    #[cfg(target_arch = "aarch64")]
    {
        crate::s101_ptrace_regs::arm64::from_user_pt_regs(u, &mut f);
        t.ptrace_stop_rax.store(u[0], Ordering::Release);
    }
    match write(t, &f) { Some(()) => Ok(()), None => Err(Errno::Esrch) }
}

/// Segment state the entry frame does not carry. `cs`/`ss` are this port's
/// fixed user selectors; `fs_base` comes from the tracee's saved `ArchCtx`;
/// `gs_base` is always 0 (no ARCH_SET_GS on this port).
#[cfg(target_arch = "x86_64")]
fn seg_state(t: &Task) -> crate::s101_ptrace_regs::x86::SegState {
    // SAFETY: the tracee is ptrace-stopped, so no CPU is running its context switch; `arch_ctx_ptr` returns its own context buffer, whose `fs_base` field the ctxsw keeps in sync with IA32_FS_BASE.
    let fs_base = unsafe { (*t.arch_ctx_ptr::<hal_x86_64::ContextX86_64>()).fs_base };
    crate::s101_ptrace_regs::x86::SegState {
        cs: hal_x86_64::USER_CS as u64,
        ss: hal_x86_64::USER_DS as u64,
        ds: 0, es: 0, fs: 0, gs: 0,
        fs_base, gs_base: 0,
    }
}
