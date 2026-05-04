// Syscall entry + sysretq return path per `20§7`. P2-01 landed the
// MSR setup + entry stub (halting dispatcher); P2-02 wires the
// sysretq epilogue and the GDT descriptors at sel 0x38/0x40/0x48
// that sysretq's selector arithmetic requires.
//
// `syscall` semantics (Intel SDM Vol. 2 + AMD APM Vol. 3):
//   - User RIP saved in rcx, user RFLAGS saved in r11.
//   - CS/SS loaded from STAR[47:32] (kernel CS) + STAR[47:32]+8.
//   - RFLAGS bits in IA32_FMASK cleared (we mask IF + DF + AC).
//   - RSP unchanged → kernel must switch stacks manually.
//
// Stack switch strategy v1: a single static scratch stack pointed at
// by `OXIDE_SYSCALL_KSTACK`. Set once at boot. Per-task RSP0 lands
// with the runqueue-wire PR (P1-84b).
//
// Argument shuffle: `syscall` ABI passes args in (rdi, rsi, rdx, r10,
// r8, r9) with nr in rax — `r10` substitutes for `rcx` because the
// instruction itself clobbers rcx with the user RIP. The Rust
// dispatcher `oxide_syscall_dispatch(nr, a0..a4)` takes 6 SysV args
// in (rdi, rsi, rdx, rcx, r8, r9). We push all source regs to the
// kernel stack then pop them back in target order to avoid clobber
// hazards mid-shuffle. a5 is discarded for the v1 smoke.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering};


const IA32_EFER:  u32 = 0xC000_0080;
const IA32_STAR:  u32 = 0xC000_0081;
const IA32_LSTAR: u32 = 0xC000_0082;
const IA32_FMASK: u32 = 0xC000_0084;

const EFER_SCE: u64 = 1 << 0;

/// SFMASK bits cleared in RFLAGS on syscall entry. IF (bit 9) keeps
/// IRQs masked through the entry critical section; DF (bit 10) so
/// `rep`/string ops have a known direction; AC (bit 18) for SMAP
/// safety once it's enabled.
const SFMASK_BITS: u64 = (1 << 9) | (1 << 10) | (1 << 18);

/// Static scratch kernel stack for syscall entry. 4 KiB, BSS,
/// 16-byte aligned.
#[repr(C, align(16))]
struct SyscallKStack(UnsafeCell<[u8; 4096]>);

// SAFETY: Single-CPU v1; the only mutator is the syscall entry stub
// which serializes its own writes via the user→kernel transition.
unsafe impl Sync for SyscallKStack {}

static SYSCALL_KSTACK: SyscallKStack = SyscallKStack(UnsafeCell::new([0u8; 4096]));

/// Top-of-stack pointer the entry asm loads into RSP. Set once at
/// boot by `install_syscall_msrs`; unchanged afterward.
#[no_mangle]
static OXIDE_SYSCALL_KSTACK: AtomicU64 = AtomicU64::new(0);

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn wrmsr(msr: u32, val: u64) {
    let lo = val as u32;
    let hi = (val >> 32) as u32;
    // SAFETY: `wrmsr` is privileged, legal at CPL=0; caller picks
    // the MSR via `msr`. Only invoked from the boot-time installer.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") lo,
            in("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: `rdmsr` is privileged, legal at CPL=0.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
core::arch::global_asm!(
    ".intel_syntax noprefix",
    ".section .text",
    ".globl oxide_syscall_entry",
    ".type  oxide_syscall_entry, @function",
    "oxide_syscall_entry:",
    "    mov  r12, rsp",                              // stash user RSP (syscall preserves r12)
    "    mov  rsp, [rip + OXIDE_SYSCALL_KSTACK]",     // switch to kernel scratch stack
    // Push everything we'll need to restore on sysretq + the
    // syscall-arg regs in source order. Stack layout after the
    // 10 pushes (low→high):
    //   [rsp+0x00] rax (nr)
    //   [rsp+0x08] rdi (a0)
    //   [rsp+0x10] rsi (a1)
    //   [rsp+0x18] rdx (a2)
    //   [rsp+0x20] r10 (a3)
    //   [rsp+0x28] r8  (a4)
    //   [rsp+0x30] r9  (a5)
    //   [rsp+0x38] rcx (user RIP)         ← reloaded into rcx pre-sysretq
    //   [rsp+0x40] r11 (user RFLAGS)      ← reloaded into r11 pre-sysretq
    //   [rsp+0x48] r12 (user RSP)         ← reloaded into rsp pre-sysretq
    "    push r12",                                    // user RSP
    "    push r11",                                    // user RFLAGS
    "    push rcx",                                    // user RIP
    "    push r9",                                     // a5
    "    push r8",                                     // a4
    "    push r10",                                    // a3
    "    push rdx",                                    // a2
    "    push rsi",                                    // a1
    "    push rdi",                                    // a0
    "    push rax",                                    // nr
    // Pop into SysV arg-reg order for oxide_syscall_dispatch(nr,
    // a0..a4) returning u64 retval in rax.
    "    pop  rdi",                                    // nr
    "    pop  rsi",                                    // a0
    "    pop  rdx",                                    // a1
    "    pop  rcx",                                    // a2
    "    pop  r8",                                     // a3
    "    pop  r9",                                     // a4
    "    pop  r10",                                    // a5 (discarded; r10 reused below)
    // After 7 pops, rsp is at the 3-quadword tail (RIP / RFLAGS /
    // RSP) on the current task's per-task syscall stack
    // (`oxide_current_kstack` updated by schedule per `13§5`).
    // SysV requires rsp 16-aligned at `call`; current offset is
    // -24 mod 16 = 8 → subtract 8 to align.
    "    sub  rsp, 8",
    "    call oxide_syscall_dispatch",                 // returns u64 retval in rax
    "    add  rsp, 8",                                 // undo align
    // Restore user state from the per-task syscall-stack tail.
    // For normal syscalls the values are exactly the captured
    // user RIP/RFLAGS/RSP from entry; `execve` (P2-21) modifies
    // them in-place via `current_user_frame()` so sysretq lands
    // the user at the new program entry.
    "    pop  rcx",                                    // user RIP
    "    pop  r11",                                    // user RFLAGS
    "    pop  rsp",                                    // user RSP (last write per sysretq spec)
    "    sysretq",
    ".size oxide_syscall_entry, . - oxide_syscall_entry",
);

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
extern "C" {
    fn oxide_syscall_entry();
}

/// Per-task user-frame slot per `13§5`. Pointers to the saved
/// (user_rip, user_rflags, user_rsp) quadwords on the current
/// task's syscall kernel stack (the 3-quadword tail left by
/// `oxide_syscall_entry` after its 7 pops, before the call to
/// dispatch). Layout: indices [0]=rip, [1]=rflags, [2]=rsp.
///
/// Used by `kernel_sys_fork` (read user RIP/RSP/RFLAGS to build
/// the child's iretq frame) and `kernel_sys_execve` (write to
/// redirect sysretq into the new program's entry without
/// returning to the caller). The asm sysretq pops from these
/// same slots — modifying them in-place is equivalent to "return
/// from the syscall as if the user had been at this RIP all
/// along".
///
/// # SAFETY: caller is `oxide_syscall_dispatch` running on the
/// active task's per-task kernel stack; the syscall asm has
/// already executed its 7 pops and the `sub rsp, 8` align before
/// calling dispatch, so this layout is current. Single-CPU UP
/// v1 — per-CPU pointer once SMP lands.
/// # C: O(1)
pub fn current_user_frame() -> *mut [u64; 3] {
    let top = OXIDE_SYSCALL_KSTACK.load(core::sync::atomic::Ordering::Acquire);
    // Top of per-task syscall stack; the 3-quadword tail begins
    // 24 B below top after the 10-pushes-then-7-pops sequence.
    (top - 24) as *mut [u64; 3]
}

// `oxide_syscall_dispatch` is defined in the kernel crate; the asm
// stub above references it by symbol. See `kernel/src/syscall_glue.rs`.

/// Update `OXIDE_SYSCALL_KSTACK` to `top` — the next syscall from
/// user mode will switch to this stack via the asm prologue. The
/// scheduler calls this on every task-switch in tandem with
/// `set_rsp0` so each user task syscalls onto its own kernel
/// stack (per-task isolation per `13§5`). Without this, two
/// user tasks sharing a single boot-time scratch stack would
/// clobber each other's syscall state if one ctx-switches mid-
/// syscall.
/// # SAFETY: caller holds the runqueue invariant for the task
/// owning this stack; preempt-off; single-CPU UP.
/// # C: O(1)
pub unsafe fn set_syscall_kstack(top: u64) {
    OXIDE_SYSCALL_KSTACK.store(top, core::sync::atomic::Ordering::Release);
}

/// Set IA32_LSTAR / IA32_STAR / IA32_FMASK + EFER.SCE for `syscall`
/// entry. One-shot per boot, called by `_start_rust` after the
/// kernel-owned GDT is in place (STAR's selector pair is keyed to
/// KERNEL_CS=0x28 / KERNEL_DS=0x30).
///
/// # SAFETY: caller is the boot path; runs single-CPU with IRQs
/// masked. MSR values agree with the kernel-owned GDT layout.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn install_syscall_msrs() {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        let top = SYSCALL_KSTACK.0.get() as u64 + 4096;
        OXIDE_SYSCALL_KSTACK.store(top, Ordering::Release);

        // SAFETY: privileged MSR writes at CPL=0; values constructed
        // from kernel-controlled constants matching the GDT.
        unsafe {
            let efer = rdmsr(IA32_EFER);
            wrmsr(IA32_EFER, efer | EFER_SCE);

            // STAR[47:32] = kernel CS base = 0x28 → kernel SS = 0x30.
            // STAR[63:48] = 0x38 → sysret-compat CS=0x38, sysret SS=0x40,
            // sysretq CS=0x48 (RPL forced to 3 by the instruction).
            // Matches `gdt::USER_CS32` / `gdt::USER_DS` / `gdt::USER_CS`.
            let star: u64 = (0x28u64 << 32) | (0x38u64 << 48);
            wrmsr(IA32_STAR, star);

            wrmsr(IA32_LSTAR, oxide_syscall_entry as *const () as usize as u64);
            wrmsr(IA32_FMASK, SFMASK_BITS);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sfmask_includes_if_df_ac() {
        assert!(SFMASK_BITS & (1 << 9)  != 0, "IF cleared on entry");
        assert!(SFMASK_BITS & (1 << 10) != 0, "DF cleared on entry");
        assert!(SFMASK_BITS & (1 << 18) != 0, "AC cleared on entry");
    }

    #[test]
    fn efer_sce_bit_position() {
        assert_eq!(EFER_SCE, 1);
    }

    #[test]
    fn syscall_kstack_size_is_4k() {
        assert_eq!(core::mem::size_of::<SyscallKStack>(), 4096);
    }
}
