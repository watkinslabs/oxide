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
// r8, r9) with nr in rax -- `r10` substitutes for `rcx` because the
// instruction itself clobbers rcx with the user RIP. The Rust
// dispatcher `oxide_syscall_dispatch(nr, a0..a4)` takes 6 SysV args
// in (rdi, rsi, rdx, rcx, r8, r9). The entry stub saves every user
// register into a `PtRegs` (`pt_regs.rs` — the SAME frame the fault
// and IRQ stubs build) and then loads the dispatcher's argument
// registers FROM that frame, so the shuffle has no clobber hazard and
// a5 stays readable (`syscalls::syscall_a5`).

use core::cell::UnsafeCell;

use crate::gdt::{USER_CS_SELECTOR, USER_SS_SELECTOR};
use crate::pt_regs::{PtRegs, PT_REGS_BYTES, PT_REGS_VECTOR_SYSCALL};

/// `PT_REGS_VECTOR_SYSCALL` in the only form `push imm` accepts: a
/// sign-extended `-1`. `push 18446744073709551615` is not encodable, so the
/// asm operand carries the signed spelling and this assert pins the two to
/// the same bit pattern.
const PT_REGS_VECTOR_SYSCALL_IMM: i64 = -1;
const _: () = assert!(PT_REGS_VECTOR_SYSCALL_IMM as u64 == PT_REGS_VECTOR_SYSCALL);

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

// B3.3 per-CPU syscall slots. The syscall entry/exit asm + the Rust frame
// readers reach these through the per-CPU area (gs base = kernel per-CPU,
// the no-swapgs model the rest of the kernel already relies on for
// `current_cpu`/percpu_base). Offsets within the 4 KiB per-CPU page; 0 is
// `cpu_id`, 8/16 were freed when Phase A removed the IRQ-tail ctx staging.
//   gs:[8]  — this CPU's per-task syscall kstack top (set by
//             `set_syscall_kstack` on every switch; was OXIDE_SYSCALL_KSTACK)
//   gs:[16] — transient user-RSP scratch within entry (was
//             OXIDE_SYSCALL_USER_RSP_SAVE)
const PERCPU_SYSCALL_KSTACK_OFF: usize = 8;
const PERCPU_SYSCALL_USER_RSP_OFF: usize = 16;
// The global_asm entry stub hardcodes `gs:[8]`/`gs:[16]` (it can't reference
// a Rust const); this pins the coupling so a layout change fails to compile.
const _: () = assert!(PERCPU_SYSCALL_KSTACK_OFF == 8 && PERCPU_SYSCALL_USER_RSP_OFF == 16);

/// Read this CPU's syscall kstack top (gs:[8]). Host build → 0.
/// # C: O(1)
#[inline]
fn percpu_syscall_kstack() -> u64 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        let v: u64;
        // SAFETY: gs base is the kernel per-CPU area (no-swapgs model);
        // offset 8 is the per-task kstack slot. Read-only.
        unsafe { core::arch::asm!("mov {v}, gs:[8]", v = out(reg) v, options(nostack, preserves_flags, readonly)); }
        v
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { 0 }
}

/// Top of the boot CPU's syscall scratch stack — the defensive initial
/// value for the BSP's `gs:[8]`, set after `set_percpu_base` (kmain). Real
/// per-task tops overwrite it on the first switch-to-user.
/// # C: O(1)
pub fn boot_syscall_kstack_top() -> u64 {
    SYSCALL_KSTACK.0.get() as u64 + 4096
}

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
    ".section .text",
    ".globl oxide_syscall_entry",
    ".type  oxide_syscall_entry, @function",
    "oxide_syscall_entry:",
    // P5-10: stash user RSP via a PER-CPU slot (gs:[16]) instead of r12
    // (the prior `mov r12, rsp` clobbered user r12). B3.3: per-CPU via the
    // gs-relative per-CPU area (gs base = kernel per-CPU, no-swapgs model)
    // so an AP syscalling concurrently with the BSP never clobbers the
    // shared scratch. gs:[8] = this CPU's per-task syscall kstack top
    // (set by set_syscall_kstack on every switch); gs:[16] = user-RSP scratch.
    "    mov  gs:[16], rsp",
    "    mov  rsp, gs:[8]",                    // switch to this CPU's kernel syscall stack
    // Build the SAME `PtRegs` the fault and IRQ stubs build (`pt_regs.rs`),
    // so one frame type serves every x86_64 entry. `syscall`/`sysretq` push
    // nothing, so the whole IRETQ-shaped tail is synthesized here:
    //   rip    <- rcx  (the insn parks the return address there)
    //   rflags <- r11  (ditto for RFLAGS)
    //   rsp    <- gs:[16] (the user RSP stashed above)
    //   cs/ss  <- the fixed ring-3 selectors `sysretq` will reload
    //   error  <- 0            (no CPU error code on a syscall)
    //   vector <- PT_REGS_VECTOR_SYSCALL (Linux tests `orig_ax != -1`)
    // Pushes run in REVERSE field order so the resulting image is
    // r15 @ +0x00 … ss @ +0xa8, size 0xb0.
    "    push {user_ss}",                      // +0xa8 ss
    "    push qword ptr gs:[16]",              // +0xa0 rsp  (user RSP)
    "    push r11",                            // +0x98 rflags
    "    push {user_cs}",                      // +0x90 cs
    "    push rcx",                            // +0x88 rip
    "    push 0",                              // +0x80 error
    "    push {vec_syscall}",                  // +0x78 vector
    "    push rax",                            // +0x70 rax (syscall nr; Linux orig_ax)
    "    push rcx",                            // +0x68 rcx (clobbered by the insn)
    "    push rdx",                            // +0x60 rdx (a2)
    "    push rsi",                            // +0x58 rsi (a1)
    "    push rdi",                            // +0x50 rdi (a0)
    "    push r8",                             // +0x48 r8  (a4)
    "    push r9",                             // +0x40 r9  (a5)
    "    push r10",                            // +0x38 r10 (a3)
    "    push r11",                            // +0x30 r11 (clobbered by the insn)
    "    push rbx",                            // +0x28
    "    push rbp",                            // +0x20
    "    push r12",                            // +0x18
    "    push r13",                            // +0x10
    "    push r14",                            // +0x08
    "    push r15",                            // +0x00
    // Move SysV-arg regs into target order WITHOUT consuming the saved
    // slots. Linux x86_64 preserves the user's rdi/rsi/rdx/r10/r8/r9 across
    // a syscall (only rax/rcx/r11 are clobbered), so the epilogue restores
    // them from this frame. Per docs/15§1.3. Sources are memory, so the
    // shuffle has no register-clobber hazard.
    "    mov  rdi, [rsp + 0x70]",              // nr <- rax
    "    mov  rsi, [rsp + 0x50]",              // a0 <- rdi
    "    mov  rdx, [rsp + 0x58]",              // a1 <- rsi
    "    mov  rcx, [rsp + 0x60]",              // a2 <- rdx
    "    mov  r8,  [rsp + 0x38]",              // a3 <- r10
    "    mov  r9,  [rsp + 0x48]",              // a4 <- r8
    // a5 (the frame's r9 slot) exceeds the 6 SysV register args and is read
    // back out of the frame by `syscalls::syscall_a5`.
    // SysV wants rsp 16-aligned AT the `call`. Entry rsp = gs:[8], a
    // 16-aligned kstack top; 22 pushes = 0xb0 ≡ 0 (mod 16) — no pad needed.
    "    call oxide_syscall_dispatch",         // returns u64 retval in rax
    // F50: arm RFLAGS.TF for PTRACE_SINGLESTEP if the current task has
    // Task.singlestep set. Called BEFORE the GPR restore below, so the
    // SysV-clobbered set needs no save/restore dance — only the dispatch
    // retval in rax has to survive (the second push is the 16-align pad,
    // since rsp is ≡ 0 (mod 16) here and the `call` needs the same).
    "    push rax",                            // dispatch retval
    "    push rax",                            // 16-align pad
    "    lea  rdi, [rsp + 0x10 + 0x98]",       // &frame.rflags (past both pushes)
    "    call oxide_x86_arm_singlestep",
    "    pop  rax",                            // drop pad
    "    pop  rax",                            // dispatch retval back
    // Restore the user GPRs from the frame. rax is NOT restored: it carries
    // the dispatch return value, and the frame's rax slot keeps the original
    // syscall nr for the whole dispatch (Linux `orig_ax`). rcx/r11 are not
    // restored either — `sysretq` requires them to be the user RIP/RFLAGS,
    // which is also exactly what the x86_64 syscall ABI says userspace may
    // assume about them (clobbered).
    "    mov  r15, [rsp + 0x00]",
    "    mov  r14, [rsp + 0x08]",
    "    mov  r13, [rsp + 0x10]",
    "    mov  r12, [rsp + 0x18]",
    "    mov  rbp, [rsp + 0x20]",
    "    mov  rbx, [rsp + 0x28]",
    "    mov  r10, [rsp + 0x38]",
    "    mov  r9,  [rsp + 0x40]",
    "    mov  r8,  [rsp + 0x48]",
    "    mov  rdi, [rsp + 0x50]",
    "    mov  rsi, [rsp + 0x58]",
    "    mov  rdx, [rsp + 0x60]",
    // Return to user through the frame's IRETQ image. `execve` (P2-21) and
    // signal delivery rewrite exactly these slots via `current_pt_regs()`, so
    // `sysretq` lands wherever they point.
    "    mov  rcx, [rsp + 0x88]",              // user RIP
    "    mov  r11, [rsp + 0x98]",              // user RFLAGS (TF possibly set above)
    "    mov  rsp, [rsp + 0xa0]",              // user RSP (last write per sysretq spec)
    // The frame itself is abandoned below the kernel rsp we just dropped;
    // the next syscall starts fresh from the kstack top.
    "    sysretq",
    ".size oxide_syscall_entry, . - oxide_syscall_entry",
    user_cs = const USER_CS_SELECTOR,
    user_ss = const USER_SS_SELECTOR,
    vec_syscall = const PT_REGS_VECTOR_SYSCALL_IMM,
);

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
extern "C" {
    fn oxide_syscall_entry();
}

/// The active task's saved `PtRegs` per `13§5` — the frame
/// `oxide_syscall_entry` pushed at the top of this CPU's per-task syscall
/// kernel stack, and the frame its epilogue returns through. Null before
/// the per-CPU kstack slot is armed (boot-only kthread path).
///
/// Used by `sys_fork` (read the parent's user state to build the child's
/// resume frame), `sys_execve` (rewrite rip/rsp/rflags so `sysretq` lands
/// in the new program without returning to the caller) and signal
/// delivery/restore. Editing the frame in place IS "return from this
/// syscall as if the user had been in that state all along".
///
/// # SAFETY (for callers dereferencing it): caller is
/// `oxide_syscall_dispatch` running on the active task's per-task kernel
/// stack, so the frame is live and singly-owned per `13§5`.
/// # C: O(1)
pub fn current_pt_regs() -> *mut PtRegs {
    let top = percpu_syscall_kstack();
    if top == 0 { return core::ptr::null_mut(); }
    (top - PT_REGS_BYTES as u64) as *mut PtRegs
}

/// Top of the active task's per-task syscall kernel stack — the value the
/// entry asm loads from `gs:[8]`, and the high end of the `PtRegs` frame
/// `current_pt_regs` derives. `0` when the slot has not been armed yet.
/// # C: O(1)
pub fn current_kstack_top() -> u64 {
    percpu_syscall_kstack()
}

// `oxide_syscall_dispatch` is defined in the kernel crate; the asm
// stub above references it by symbol. See `kernel/src/syscall_glue.rs`.

/// Update `OXIDE_SYSCALL_KSTACK` to `top` -- the next syscall from
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
    // Write THIS CPU's per-task kstack slot (gs:[8]). Called from schedule()
    // on every switch (after set_percpu_base, so gs is valid). The next
    // syscall on this CPU loads it via the entry stub.
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    // SAFETY: gs base = kernel per-CPU area (no-swapgs); offset 8 is the
    // per-task syscall-kstack slot within the 4 KiB per-CPU page.
    unsafe { core::arch::asm!("mov gs:[8], {v}", v = in(reg) top, options(nostack, preserves_flags)); }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { let _ = top; }
}

/// Initialise THIS CPU's syscall-kstack slot (gs:[8]) to a known stack —
/// called from kmain right AFTER `set_percpu_base` (gs valid). Defensive:
/// the first switch-to-user overwrites it via `set_syscall_kstack`, but
/// this guards against any syscall before the first schedule. The BSP
/// passes `boot_syscall_kstack_top()`; an AP passes its own scratch top.
/// # SAFETY: gs must already point at this CPU's per-CPU area.
/// # C: O(1)
pub unsafe fn init_percpu_syscall_kstack(top: u64) {
    // SAFETY: per fn contract — gs is the per-CPU area; same slot as set_syscall_kstack.
    unsafe { set_syscall_kstack(top); }
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
        // NOTE: do NOT init gs:[8] here — install_syscall_msrs runs in EARLY
        // boot (before set_percpu_base sets gs). kmain calls
        // init_percpu_syscall_kstack after gs is up; per-task tops then come
        // from set_syscall_kstack on each switch.

        // SAFETY: privileged MSR writes at CPL=0; values constructed
        // from kernel-controlled constants matching the GDT.
        unsafe {
            let efer = rdmsr(IA32_EFER);
            wrmsr(IA32_EFER, efer | EFER_SCE);

            // STAR[47:32] = kernel CS base = 0x28 → kernel SS = 0x30.
            // STAR[63:48] = (USER_CS32 | 3) = 0x3B. sysretq derives
            //   CS = STAR[63:48] + 16  → 0x4B (= USER_CS with RPL=3)
            //   SS = STAR[63:48] +  8  → 0x43 (= USER_DS with RPL=3)
            // On Intel SYSRET, RPL is force-ORed to 3 on both CS and
            // SS. On AMD (and KVM emulating AMD-style SYSRET), the OR
            // happens only for CS — SS comes out exactly as
            // STAR[63:48]+8 with no RPL fixup. If STAR[63:48] were
            // 0x38 (no RPL bits), SS on AMD/KVM-AMD would land as
            // 0x40 (RPL=0), and the next CPL3 IRQ would push that
            // bare-RPL SS into its iretq frame; iretq back to ring 3
            // then #GP's because SS.RPL != CS.RPL. Linux bakes RPL=3
            // into STAR's user-selector for the same reason.
            let star: u64 = (0x28u64 << 32) | (((crate::gdt::USER_CS32 as u64) & 0xFFFF) << 48);
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

    #[test]
    fn the_entry_stub_pushes_exactly_one_pt_regs() {
        // 22 `push`es in `oxide_syscall_entry`; the frame it leaves is what
        // `current_pt_regs()` re-derives from the kstack top.
        assert_eq!(PT_REGS_BYTES, 22 * 8);
        // ...and that count keeps rsp 16-aligned at the `call`, which is why
        // the stub needs no alignment pad before `oxide_syscall_dispatch`.
        assert_eq!(PT_REGS_BYTES % 16, 0, "entry pushes must not skew the SysV alignment");
    }

    #[test]
    fn the_syscall_vector_sentinel_survives_the_asm_immediate() {
        // `push -1` is what the assembler accepts; `from_syscall()` tests
        // against the u64 spelling.
        assert_eq!(PT_REGS_VECTOR_SYSCALL_IMM as u64, PT_REGS_VECTOR_SYSCALL);
        assert_eq!(PT_REGS_VECTOR_SYSCALL, u64::MAX);
    }

    #[test]
    fn the_synthesized_selectors_are_the_ring3_gdt_pair() {
        // The IRETQ image `syscall` does not push is synthesized from these;
        // they must be the very selectors `sysretq` reloads (gdt.rs STAR
        // arithmetic), or the first IRQ from ring 3 pushes a mismatched SS.
        assert_eq!(USER_CS_SELECTOR, crate::gdt::USER_CS as u64);
        assert_eq!(USER_SS_SELECTOR, crate::gdt::USER_DS as u64);
        assert_eq!(USER_CS_SELECTOR & 3, 3);
        assert_eq!(USER_SS_SELECTOR & 3, 3);
    }
}
