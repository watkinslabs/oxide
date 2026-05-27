// F205: the 6th syscall arg (a5) is dropped by the standard SysV
// C-ABI dispatch fn signature — nr + a0..a4 already consume all 6
// reg-passable args. Read a5 directly from the arch-saved syscall
// frame the entry asm stashed before shuffling user regs into the
// C-ABI slots.
//
// Without this, sys_pselect6's sigmask_pair argument is silently
// dropped, and any 6-arg syscall the future-Linux ABI grows would
// see a5 = 0.

#![cfg(target_os = "oxide-kernel")]

/// Read user-supplied a5 from the active syscall-entry save block.
/// Returns 0 if no live save block is available (pre-init).
/// # SAFETY: caller is `oxide_syscall_dispatch` running on the
/// active task's per-task syscall kernel stack; the per-arch save
/// block was published by the entry asm before `bl` to the
/// dispatcher. Single-CPU UP per `13§5`.
/// # C: O(1)
#[inline]
pub unsafe fn read() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        // x86 entry pushes [rsp+0x00] nr, [+0x08] a0, ..., [+0x30] a5.
        let p = hal_x86_64::current_user_full_frame();
        if p.is_null() { 0 } else {
            // SAFETY: p is a valid pointer to a 16-quadword block on the running task's kernel stack; index 6 is the a5 slot per oxide_syscall_entry's push order; aligned u64 read.
            unsafe { *p.add(6) }
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        // ARM SVC entry saves x0..x5 at [sp+0x00..0x28] BEFORE the
        // shuffle to the C-ABI dispatch. x5 (orig a5) is at +0x28.
        let p = hal_aarch64::current_svc_frame();
        if p.is_null() { 0 } else {
            // SAFETY: current_svc_frame returns the saved SVC frame on the running task's kernel stack; sole writer for the lifetime of this dispatch per `13§5` single-mutator; reading gp[5] is a plain u64 load through a valid SvcFrame.
            unsafe { (*p).gp[5] }
        }
    }
}
