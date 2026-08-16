// The two halves of the deep-sleep control transfer.
//
// `oxide_suspend_lowlevel` is the only place that can name the resume point:
// it captures the callee-saved registers, the stack pointer, the flags word
// and the address of its OWN continuation, hands the machine to the platform
// enter, and lands the resume back on that continuation. A Rust function
// cannot do this — the resume arrives with no stack, no descriptor tables and
// no return address, so the landing has to be an instruction, not a `ret`.
//
// `oxide_wakeup_long64` is where the real-mode trampoline arrives once long
// mode is back. It runs on the trampoline's own GDT with the kernel page
// tables loaded and NOTHING else restored: no IDT, no TSS, no per-CPU base.
// It therefore touches no stack and no `gs:`-relative memory, checks the
// armed magic, and jumps. A firmware that resumes here with the record
// unarmed has resumed somewhere this kernel did not ask for, and halting is
// the only thing left that is not executing garbage.
//
// `54§1.4`: `rbx`, `rbp` and `r12`-`r15` are callee-saved by the C ABI, so
// the entry pushes them before touching any of them, and the resume path
// restores them from the record rather than from the stack — one source of
// truth for what the sleep preserved.

use super::state::SavedCpuState;

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
core::arch::global_asm!(
    ".section .text",
    ".globl oxide_suspend_lowlevel",
    ".type  oxide_suspend_lowlevel, @function",
    // rdi = &mut SavedCpuState, rsi = extern "C" fn() -> u64.
    "oxide_suspend_lowlevel:",
    "    push rbp",
    "    push rbx",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",
    "    mov  [rdi + {off_rbx}], rbx",
    "    mov  [rdi + {off_rbp}], rbp",
    "    mov  [rdi + {off_r12}], r12",
    "    mov  [rdi + {off_r13}], r13",
    "    mov  [rdi + {off_r14}], r14",
    "    mov  [rdi + {off_r15}], r15",
    "    pushfq",
    "    pop  rax",
    "    mov  [rdi + {off_rflags}], rax",
    "    mov  [rdi + {off_rsp}], rsp",
    "    mov  [rdi + {off_resume_rsp}], rsp",
    "    lea  rax, [rip + 2f]",
    "    mov  [rdi + {off_resume_rip}], rax",
    "    mov  rax, {magic}",
    "    mov  [rdi + {off_magic}], rax",
    "    xor  eax, eax",
    "    mov  [rdi + {off_result}], rax",
    "    mov  [rip + oxide_suspend_record], rdi",
    // One push restores the 16-byte alignment the SysV ABI requires at a
    // call, and keeps the record pointer across it.
    "    mov  rax, rsi",
    "    push rdi",
    "    call rax",
    "    pop  rdi",
    "    mov  [rdi + {off_result}], rax",
    // The enter returned, so no sleep happened. Take the same path the
    // resume takes: the restore is idempotent and the caller reads the
    // result out of the record either way.
    "2:",
    "    mov  rdi, [rip + oxide_suspend_record]",
    "    mov  rax, [rdi + {off_cr4}]",
    "    mov  cr4, rax",
    "    mov  rax, [rdi + {off_cr3}]",
    "    mov  cr3, rax",
    "    mov  rax, [rdi + {off_cr2}]",
    "    mov  cr2, rax",
    "    mov  rax, [rdi + {off_cr0}]",
    "    mov  cr0, rax",
    "    mov  rsp, [rdi + {off_resume_rsp}]",
    "    push qword ptr [rdi + {off_rflags}]",
    "    popfq",
    "    mov  rbx, [rdi + {off_rbx}]",
    "    mov  rbp, [rdi + {off_rbp}]",
    "    mov  r12, [rdi + {off_r12}]",
    "    mov  r13, [rdi + {off_r13}]",
    "    mov  r14, [rdi + {off_r14}]",
    "    mov  r15, [rdi + {off_r15}]",
    "    xor  eax, eax",
    "    mov  [rdi + {off_magic}], rax",
    "    mov  rax, [rdi + {off_result}]",
    // Drop the six pushed copies; the record was the restore's source.
    "    add  rsp, 48",
    "    ret",
    ".size oxide_suspend_lowlevel, . - oxide_suspend_lowlevel",

    ".globl oxide_wakeup_long64",
    ".type  oxide_wakeup_long64, @function",
    "oxide_wakeup_long64:",
    "    mov  rax, [rip + oxide_suspend_record]",
    "    test rax, rax",
    "    jz   3f",
    "    mov  rcx, [rax + {off_magic}]",
    "    mov  rdx, {magic}",
    "    cmp  rcx, rdx",
    "    jne  3f",
    "    mov  rcx, [rax + {off_resume_rip}]",
    "    jmp  rcx",
    "3:",
    "    cli",
    "    hlt",
    "    jmp  3b",
    ".size oxide_wakeup_long64, . - oxide_wakeup_long64",

    ".section .data",
    ".balign 8",
    ".globl oxide_suspend_record",
    "oxide_suspend_record: .quad 0",
    ".section .text",

    off_rbx = const super::state::OFF_REGS_RBX,
    off_rbp = const super::state::OFF_REGS_RBP,
    off_r12 = const super::state::OFF_REGS_R12,
    off_r13 = const super::state::OFF_REGS_R13,
    off_r14 = const super::state::OFF_REGS_R14,
    off_r15 = const super::state::OFF_REGS_R15,
    off_rsp = const super::state::OFF_REGS_RSP,
    off_rflags = const super::state::OFF_REGS_RFLAGS,
    off_resume_rip = const super::state::OFF_RESUME_RIP,
    off_resume_rsp = const super::state::OFF_RESUME_RSP,
    off_magic = const super::state::OFF_MAGIC,
    off_result = const super::state::OFF_ENTER_RESULT,
    off_cr0 = const super::state::OFF_CR0,
    off_cr2 = const super::state::OFF_CR2,
    off_cr3 = const super::state::OFF_CR3,
    off_cr4 = const super::state::OFF_CR4,
    magic = const super::state::SUSPEND_MAGIC,
);

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
extern "C" {
    fn oxide_suspend_lowlevel(state: *mut SavedCpuState, enter: extern "C" fn() -> u64) -> u64;
    fn oxide_wakeup_long64();
}

/// Hand the machine to `enter`, and come back here — either because `enter`
/// returned without sleeping, or because firmware resumed through the waking
/// vector into [`wakeup_entry`]. Returns whatever `enter` returned; zero
/// after a real sleep, because the resume path never ran the store.
///
/// # SAFETY: CPL=0, interrupts disabled, one CPU online, and `state` already
/// carries a `save_processor_state` snapshot. The record must stay alive and
/// unmoved until this returns — the resume path finds it through a static.
/// # C: O(1)
/// # Ctx: IRQ-off, single-CPU
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn suspend_lowlevel(state: &mut SavedCpuState, enter: extern "C" fn() -> u64) -> u64 {
    // SAFETY: per fn contract — the asm reads and writes only `state` and its own static, and returns to this frame.
    unsafe { oxide_suspend_lowlevel(state as *mut SavedCpuState, enter) }
}

/// Kernel virtual address the real-mode trampoline jumps to once long mode
/// is back. The trampoline cannot encode it as a far-jump immediate, so it
/// loads it from its patched data block.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub fn wakeup_entry() -> u64 { oxide_wakeup_long64 as *const () as u64 }

/// Hosted build: no privileged control transfer exists, so the platform
/// enter runs in place and its result is reported the same way.
/// # SAFETY: no privileged state is touched. # C: O(1)
#[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
pub unsafe fn suspend_lowlevel(state: &mut SavedCpuState, enter: extern "C" fn() -> u64) -> u64 {
    state.magic = super::state::SUSPEND_MAGIC;
    let r = enter();
    state.enter_result = r;
    state.magic = 0;
    r
}

/// Hosted build counterpart: no trampoline, so no entry address. # C: O(1)
#[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
pub fn wakeup_entry() -> u64 { 0 }
