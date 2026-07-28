// 335 uretprobe — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_uretprobe()` — slot 335. Not a userspace API: the kernel injects the
/// call at the return site of a uprobe return-probe, with
/// `struct uretprobe_syscall_args` staged on the user stack. `SYSCALL_DEFINE0
/// (uretprobe)` (`arch/x86/kernel/uprobes.c`) validates three things before
/// touching that frame — a trampoline exists, `regs->ip` equals
/// `trampoline_check_ip(tramp)`, and the args copy in — and every failure
/// jumps to `sigill:`, i.e. `force_sig(SIGILL)`.
///
/// oxide installs no uprobe trampoline, so `uprobe_get_trampoline_vaddr()` is
/// unconditionally `UPROBE_NO_TRAMPOLINE_VADDR` and EVERY call takes the first
/// `goto sigill`. `force_sig` resets the disposition to `SIG_DFL` and unblocks
/// the signal first, so the caller cannot catch, ignore or block its way out —
/// which is why this terminates rather than merely setting the pending bit.
///
/// The slot exists on x86_64 only: 335 is in
/// `arch/x86/entry/syscalls/syscall_64.tbl` and absent from
/// `include/uapi/asm-generic/unistd.h`, where "295 through 402 are unassigned".
/// `syscall::arm_abi::arm_nr_is_unassigned` keeps an aarch64 caller out of here.
/// # C: O(1)
pub fn sys_uretprobe(_args: &SyscallArgs) -> i64 {
    sched::live::terminate_current_with_signal(sched::signum::Signum::Sigill.as_u8())
}
