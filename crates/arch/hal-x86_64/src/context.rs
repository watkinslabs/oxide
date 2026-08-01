// x86_64 `Context` impl per `14§5`. The single asm symbol
// `oxide_context_switch` lives here (gated to the kernel target);
// host builds substitute a no-op extern fn so call-site checks
// exercise the trait surface without invoking real asm.
//
// Layout per `14§5.2`: 8 callee-saved + fs_base + gs_base, repr(C), 72 B.
// Offsets are asm-coupled — the inline assembly references `[rdi +
// 0x00]`, `[rsi + 0x00]`, etc. — so any field reordering breaks the
// switch. Tests pin every offset.

use hal::Context;

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
use crate::cpu::{rdmsr, wrmsr};

use crate::pt_regs::{PtRegs, PT_REGS_BYTES};

/// Bytes a first-run task's scaffold occupies below `stack_top`: the saved
/// RIP `oxide_context_switch`'s `ret` pops, then the `PtRegs`
/// `oxide_irq_resume_user` pops and `iretq`s.
const SCAFFOLD_BYTES: usize = core::mem::size_of::<u64>() + PT_REGS_BYTES;

/// RFLAGS a first-run task starts with: IF=1 (preemptible by the LAPIC
/// timer) plus the always-set reserved bit 1. Ring 3 can neither `sti` nor
/// `cli` (IOPL=0), so this IS what user runs with for its lifetime.
const SCAFFOLD_RFLAGS: u64 = 0x202;

/// Synthetic vector tag the kthread scaffold carries, mirroring what the
/// LAPIC-timer stub (`oxide_irq_vec_40`) would have pushed. Never consumed
/// — `oxide_irq_resume_user` drops the (vector, error) pair — but a real
/// vector reads better than 0 in a dump.
const SCAFFOLD_VECTOR: u64 = crate::irq::VEC_TIMER as u64;

/// Write a first-run scaffold `regs` image below `stack_top` and return the
/// resulting `Context.rsp` (the saved-RIP slot at scaffold base).
///
/// The image is written THROUGH `PtRegs` fields rather than raw stack
/// offsets, so the layout can only drift if `pt_regs.rs` itself changes —
/// which its const asserts forbid.
///
/// # SAFETY: `stack_top` is the high end of a writable, 16-byte-aligned
/// kernel stack with at least `SCAFFOLD_BYTES` below it; the caller owns
/// that stack until the task is scheduled.
/// # C: O(1)
unsafe fn write_scaffold(stack_top: *mut u8, regs: PtRegs) -> u64 {
    // SAFETY: per fn contract — `[stack_top - SCAFFOLD_BYTES, stack_top)` is
    // writable kernel stack we exclusively own here. `stack_top` is
    // 16-aligned and `PT_REGS_BYTES` is a multiple of 16, so the `PtRegs`
    // store is naturally aligned.
    unsafe {
        let base = stack_top.sub(SCAFFOLD_BYTES);
        core::ptr::write(base.add(core::mem::size_of::<u64>()).cast::<PtRegs>(), regs);
        // Saved RIP for `oxide_context_switch`'s `ret`: the finish-switch
        // trampoline pays the switch handoff, then jmps the shared epilogue.
        core::ptr::write(base.cast::<u64>(), finish_switch_tramp_addr());
        base as u64
    }
}

/// Saved kernel-state register set per `14§5.2`. Field order is
/// asm-coupled; do not reorder.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct ContextX86_64 {
    pub rsp:     u64, // 0x00
    pub rbp:     u64, // 0x08
    pub rbx:     u64, // 0x10
    pub r12:     u64, // 0x18 — trampoline reads `entry` from here
    pub r13:     u64, // 0x20 — trampoline reads `arg` from here
    pub r14:     u64, // 0x28
    pub r15:     u64, // 0x30
    pub fs_base: u64, // 0x38 — reloaded into IA32_FS_BASE by the switch
    /// This thread's USER GS base (`arch_prctl(ARCH_SET_GS)`), 0 by default.
    /// Kernel mode keeps it in `IA32_KERNEL_GS_BASE` — the register `swapgs`
    /// exchanges with the live GS base on every ring transition — so the
    /// switch reloads THAT MSR, not `IA32_GS_BASE` (which holds this CPU's
    /// per-CPU area and is not per-task at all).
    pub gs_base: u64, // 0x40
}

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
core::arch::global_asm!(
    ".section .text",
    ".globl oxide_context_switch",
    ".type  oxide_context_switch, @function",
    "oxide_context_switch:",
    "    mov  [rdi + 0x00], rsp",
    "    mov  [rdi + 0x08], rbp",
    "    mov  [rdi + 0x10], rbx",
    "    mov  [rdi + 0x18], r12",
    "    mov  [rdi + 0x20], r13",
    "    mov  [rdi + 0x28], r14",
    "    mov  [rdi + 0x30], r15",
    "    mov  rsp, [rsi + 0x00]",
    "    mov  rbp, [rsi + 0x08]",
    "    mov  rbx, [rsi + 0x10]",
    "    mov  r12, [rsi + 0x18]",
    "    mov  r13, [rsi + 0x20]",
    "    mov  r14, [rsi + 0x28]",
    "    mov  r15, [rsi + 0x30]",
    // F243: load next's saved fs_base into IA32_FS_BASE MSR so
    // first-run tasks (CLONE_SETTLS / fork) start with the correct
    // user TLS. wrmsr clobbers rcx/rax/rdx — those are caller-
    // saved per SysV and the Rust caller doesn't read them post-call.
    "    mov  rax, [rsi + 0x38]",
    "    mov  rdx, rax",
    "    shr  rdx, 32",
    "    mov  ecx, {msr_fs_base}",
    "    wrmsr",
    // Same for next's user GS base, into IA32_KERNEL_GS_BASE. We are in
    // kernel mode, so the live IA32_GS_BASE is this CPU's per-CPU area (which
    // must NOT move) and the shadow register is where the outgoing thread's
    // user base sits; the exit-path `swapgs` promotes it on the way to ring 3.
    "    mov  rax, [rsi + 0x40]",
    "    mov  rdx, rax",
    "    shr  rdx, 32",
    "    mov  ecx, {msr_kernel_gs_base}",
    "    wrmsr",
    "    ret",
    ".size oxide_context_switch, . - oxide_context_switch",
    msr_fs_base = const crate::msr::IA32_FS_BASE,
    msr_kernel_gs_base = const crate::msr::IA32_KERNEL_GS_BASE,
);

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
core::arch::global_asm!(
    ".section .text",
    ".globl oxide_trampoline_kernel",
    ".type  oxide_trampoline_kernel, @function",
    "oxide_trampoline_kernel:",
    "    mov rdi, r13",
    "    jmp r12",
    ".size oxide_trampoline_kernel, . - oxide_trampoline_kernel",
);

// First-run `finish_task_switch` trampoline (`smp-arch.md` Phase A step 0).
// Baked as the saved-RIP at the bottom of every `new_*_with_irq_frame`
// scaffold (replacing the bare `oxide_irq_resume_user`): when
// `oxide_context_switch`'s `ret` lands here on a fresh task's first run, it
// pays the switch handoff (`oxide_finish_task_switch` = preempt-enable +
// IRQ-enable, defined in the sched crate) before dropping into the shared
// epilogue's `iretq` to user/kernel. Resumed existing tasks pay the same −1
// inline from `schedule()`; both reach `finish_task_switch` exactly once.
// Stack alignment at entry: `oxide_context_switch`'s `ret` left rsp 16-byte
// aligned (scaffold base + 8), so `call` is ABI-correct.
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
core::arch::global_asm!(
    ".section .text",
    ".globl oxide_finish_switch_tramp",
    ".type  oxide_finish_switch_tramp, @function",
    "oxide_finish_switch_tramp:",
    "    call oxide_finish_task_switch",
    "    jmp  oxide_irq_resume_user",
    ".size oxide_finish_switch_tramp, . - oxide_finish_switch_tramp",
);

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
extern "C" {
    fn oxide_context_switch(prev: *mut ContextX86_64, next: *const ContextX86_64);
    fn oxide_trampoline_kernel() -> !;
    fn oxide_finish_switch_tramp() -> !;
}

/// Address of `oxide_finish_switch_tramp` — the saved-RIP value baked at
/// the bottom of every `new_*_with_irq_frame` scaffold so a first-run task
/// pays the `finish_task_switch` handoff before its first user return.
/// Host build returns 0 (asm symbol absent).
/// # C: O(1)
fn finish_switch_tramp_addr() -> u64 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { oxide_finish_switch_tramp as *const () as usize as u64 }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { 0 }
}

/// Kernel-target trampoline address; host build returns 0 since
/// `Context::switch` is a no-op there anyway.
fn trampoline_kernel_addr() -> u64 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { oxide_trampoline_kernel as *const () as usize as u64 }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { 0 }
}

impl Context for ContextX86_64 {
    /// Build a kernel-thread context that, on first `switch`-to,
    /// jumps to `oxide_trampoline_kernel` which loads `entry` from
    /// `r12` and `arg` from `r13` and tail-jumps to `entry(arg)`.
    /// `stack_top` is the high end of the kernel stack; we push the
    /// trampoline return address into the topmost slot so the first
    /// `ret` lands there.
    /// # C: O(1)
    fn new_kernel(stack_top: *mut u8, entry: extern "C" fn(usize) -> !, arg: usize) -> Self {
        // SAFETY: caller asserts `stack_top` points to the high end
        // of a writable, 16-byte-aligned kernel stack of at least
        // 8 bytes; we write the trampoline return slot one u64 below.
        let sp = unsafe {
            let p = stack_top.cast::<u64>().sub(1);
            p.write(trampoline_kernel_addr());
            p
        };
        Self {
            rsp: sp as u64,
            rbp: 0,
            rbx: 0,
            r12: entry as *const () as usize as u64,
            r13: arg as u64,
            r14: 0,
            r15: 0,
            fs_base: 0,
            gs_base: 0,
        }
    }

    /// Build a kernel-thread context whose saved kernel stack carries a
    /// synthetic entry frame matching what the IRQ epilogue
    /// (`oxide_irq_resume_user`) pops. Lets the scheduler `Context::switch`
    /// directly into a fresh task and `iretq` from the same epilogue.
    /// Layout pinned in `14§R07`; scaffold = saved-RIP + one `PtRegs` =
    /// 8 + 0xb0 = 184 B starting at `Context.rsp`, growing toward
    /// `stack_top`:
    ///
    ///   [rsp+0x00]        saved RIP = oxide_finish_switch_tramp
    ///   [rsp+0x08..0xb8]  `PtRegs` (GPRs zero; vector/error tag; IRETQ
    ///                     image = trampoline / KERNEL_CS / IF=1 /
    ///                     stack_top / KERNEL_DS)
    ///
    /// `stack_top` is the post-iretq RSP — the kthread runs with the whole
    /// stack below it. `r12 = entry`, `r13 = arg` per the trampoline ABI,
    /// staged in the FRAME as well as in `Context`: the epilogue now pops
    /// the callee-saved set too (it must, so an IRQ-return signal delivery
    /// sees real rbx/rbp/r12-r15), which would otherwise overwrite the
    /// values `oxide_context_switch` loaded from `Context` with zeros.
    ///
    /// # C: O(1)
    fn new_kernel_with_irq_frame(
        stack_top: *mut u8,
        entry: extern "C" fn(usize) -> !,
        arg: usize,
    ) -> Self {
        // Selectors per Limine v6+ GDT layout: code = 0x28 (64-bit kernel
        // CS), data = 0x30 (64-bit kernel DS/SS).
        let regs = PtRegs {
            r12:    entry as *const () as usize as u64,
            r13:    arg as u64,
            vector: SCAFFOLD_VECTOR,
            rip:    trampoline_kernel_addr(),
            cs:     crate::idt::KERNEL_CS as u64,
            rflags: SCAFFOLD_RFLAGS,
            rsp:    stack_top as u64,
            ss:     crate::gdt::KERNEL_DS as u64,
            ..Default::default()
        };
        // SAFETY: caller asserts `stack_top` is the high end of a writable,
        // 16-byte-aligned kernel stack of at least SCAFFOLD_BYTES.
        let sp = unsafe { write_scaffold(stack_top, regs) };
        Self {
            rsp: sp,
            rbp: 0,
            rbx: 0,
            r12: entry as *const () as usize as u64,
            r13: arg as u64,
            r14: 0,
            r15: 0,
            fs_base: 0,
            gs_base: 0,
        }
    }

    /// Build a context for first-entry into user-mode. The actual
    /// transition (`iretq` to user CS:RIP / SS:RSP) happens in the
    /// syscall/IRQ-exit asm in `20§*` — this just stages the values
    /// the trampoline reads. r13 = user_sp, r14 = user_ip; trampoline
    /// for user entry lands alongside the syscall return path.
    /// # C: O(1)
    fn new_user(stack_top: *mut u8, user_ip: u64, user_sp: u64) -> Self {
        Self {
            rsp: stack_top as u64,
            rbp: 0,
            rbx: 0,
            r12: 0,
            r13: user_sp,
            r14: user_ip,
            r15: 0,
            fs_base: 0,
            gs_base: 0,
        }
    }

    /// # SAFETY: `prev` and `next` reference valid `Context` records;
    /// `next`'s saved stack is a valid kernel stack with the
    /// trampoline (or a frame from a prior switch) at `[rsp]`;
    /// preempt disabled; runqueue lock held by caller and released
    /// by the next thread post-switch per `14§4`.
    /// # C: O(1)
    /// # Ctx: process|irq-return path; preempt-off
    unsafe fn switch(prev: *mut Self, next: *const Self) {
        #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
        {
            // Save the live FS_BASE into `prev->fs_base` and restore
            // `next->fs_base` afterwards. Userspace musl uses FS-
            // relative pthread storage; without this, a child task
            // that called `arch_prctl(SET_FS, ...)` leaves the CPU
            // FS_BASE pointing at *its* TLS region, which faults the
            // moment the parent runs again.
            // SAFETY: rdmsr IA32_FS_BASE legal at CPL=0; reads only the FS_BASE MSR.
            let cur_fs: u64 = unsafe { rdmsr(crate::msr::IA32_FS_BASE) };
            // The outgoing thread's USER GS base lives in IA32_KERNEL_GS_BASE
            // while we are in kernel mode (the live GS base is this CPU's
            // per-CPU area). Same staleness argument as fs_base: arch_prctl
            // writes the MSR directly, so the MSR — not the saved field — is
            // the truth at this instant.
            // SAFETY: rdmsr IA32_KERNEL_GS_BASE legal at CPL=0; reads only that MSR.
            let cur_gs: u64 = unsafe { rdmsr(crate::msr::IA32_KERNEL_GS_BASE) };
            // SAFETY: prev is a valid &mut Self per fn contract.
            unsafe { (*prev).fs_base = cur_fs; (*prev).gs_base = cur_gs; }
            // SAFETY: `oxide_context_switch` OVERWRITES rsp/rbp/rbx/r12-r15
            // with the incoming task's saved values — that IS the switch
            // (see its global_asm! body: every one of those regs is loaded
            // from `next` before the `ret`). Per docs/54 §1.4 ("an asm stub
            // that clobbers r12-r15/rbx/rbp across a call must push first"),
            // a plain `extern "C"` call site here would let LLVM assume the
            // normal SysV callee-saved contract and keep `prev` live in one
            // of those exact registers across the call — after which it
            // would silently alias whatever the INCOMING task's Context
            // happened to store in that slot (observed live: a corrupted
            // resume reading a stray task's r13 field). Routing through
            // inline asm with explicit clobbers forces the compiler to
            // spill `prev`/`next` to the stack instead, which the call/ret
            // discipline correctly restores when this exact task resumes.
            // rbx/rbp are not declared as clobbers below: this target
            // reserves both from LLVM's own register allocator (rbx
            // globally; rbp as the permanent frame pointer, per
            // `"frame-pointer": "always"`), so LLVM never places an
            // ordinary Rust value in either — only r12-r15 are reachable
            // by the register allocator and need declaring here.
            unsafe {
                core::arch::asm!(
                    "call {switch_fn}",
                    switch_fn = sym oxide_context_switch,
                    in("rdi") prev,
                    in("rsi") next,
                    lateout("r12") _, lateout("r13") _,
                    lateout("r14") _, lateout("r15") _,
                    clobber_abi("C"),
                );
            }
            // We're back on this task's stack (some other call to
            // Context::switch eventually picked us). The Rust
            // locals `prev`, `next` here are bound to the original
            // outgoing call's frame — `prev` points at this task's
            // own ctx — so we restore from `(*prev).fs_base`, NOT
            // `(*next).fs_base` (which would be the unrelated task
            // we *originally* switched into).
            // SAFETY: prev is a valid *mut Self per fn contract; wrmsr of the two per-thread segment-base MSRs is legal at CPL=0.
            unsafe {
                wrmsr(crate::msr::IA32_FS_BASE, (*prev).fs_base);
                wrmsr(crate::msr::IA32_KERNEL_GS_BASE, (*prev).gs_base);
            }
        }
        #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
        {
            // Host fallback: no real switch on the host CPU; just
            // touch the pointers so the borrow-checker sees them.
            let _ = (prev, next);
        }
    }
}

impl ContextX86_64 {
    /// User-mode flavor of `new_kernel_with_irq_frame`. The synthetic
    /// frame uses USER selectors (DPL=3) and `iretq` therefore
    /// transitions to ring 3 with CS=`USER_CS`, SS=`USER_DS`, RIP=
    /// `user_ip`, RSP=`user_sp`. RFLAGS=0x202 (IF=1, reserved bit 1)
    /// so user tasks are preemptible by the LAPIC timer. Ring-3 can
    /// neither sti nor cli (IOPL=0), so the IF state baked into the
    /// frame is what user runs with for its lifetime.
    ///
    /// Layout matches the kernel-mode flavor — the same `PtRegs` — so the
    /// shared `oxide_irq_resume_user` epilogue iretq's into ring 3 instead
    /// of staying at CPL=0. Inherent on `ContextX86_64` (not on the
    /// `hal::Context` trait): arm parity rides a follow-up that adds
    /// sp_el0 save/restore to the IRQ frame.
    /// # C: O(1)
    pub fn new_user_with_irq_frame(stack_top: *mut u8, user_ip: u64, user_sp: u64) -> Self {
        // USER CS/SS per `36-bootloader-handoff` GDT (P1-93): USER_CS =
        // 0x4B (DPL=3 64-bit code), USER_DS = 0x43 (DPL=3 data).
        let regs = PtRegs {
            rip:    user_ip,
            cs:     crate::gdt::USER_CS_SELECTOR,
            rflags: SCAFFOLD_RFLAGS,
            rsp:    user_sp,
            ss:     crate::gdt::USER_SS_SELECTOR,
            ..Default::default()
        };
        // SAFETY: caller asserts `stack_top` is the high end of a writable,
        // 16-byte-aligned kernel stack of at least SCAFFOLD_BYTES.
        let sp = unsafe { write_scaffold(stack_top, regs) };
        Self {
            rsp: sp,
            rbp: 0,
            rbx: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            fs_base: 0,
            gs_base: 0,
        }
    }

    /// Fork-specific user-task scaffold (P5-10): the same frame shape as
    /// `new_user_with_irq_frame`, populated from the parent's live
    /// `PtRegs` so the child resumes user mode with the identical register
    /// state — except `rax` is 0 (the fork return value the child sees).
    ///
    /// Every GPR now lives in the FRAME, because `oxide_irq_resume_user`
    /// pops the callee-saved set as well; the matching `Context` fields
    /// are kept in step so a resumed (non-first-run) switch is identical.
    /// `user_ip`/`user_sp`/`user_rflags` are passed separately: a thread
    /// clone overrides the stack, and `sys_clone` already resolved them.
    /// # C: O(1)
    pub fn new_user_for_fork(
        stack_top: *mut u8,
        user_ip: u64,
        user_sp: u64,
        user_rflags: u64,
        regs: &ForkRegs,
        parent_fs_base: u64,
        parent_gs_base: u64,
    ) -> Self {
        let frame = PtRegs {
            r15: regs.r15, r14: regs.r14, r13: regs.r13, r12: regs.r12,
            rbp: regs.rbp, rbx: regs.rbx,
            r11: regs.r11, r10: regs.r10, r9: regs.r9, r8: regs.r8,
            rdi: regs.rdi, rsi: regs.rsi, rdx: regs.rdx, rcx: regs.rcx,
            rax: 0,                                  // child's fork(2) return
            vector: 0, error: 0,
            rip:    user_ip,
            cs:     crate::gdt::USER_CS_SELECTOR,
            rflags: user_rflags,
            rsp:    user_sp,
            ss:     crate::gdt::USER_SS_SELECTOR,
        };
        // SAFETY: same as `new_user_with_irq_frame`.
        let sp = unsafe { write_scaffold(stack_top, frame) };
        Self {
            rsp: sp,
            rbp: regs.rbp,
            rbx: regs.rbx,
            r12: regs.r12,
            r13: regs.r13,
            r14: regs.r14,
            r15: regs.r15,
            fs_base: parent_fs_base,
            gs_base: parent_gs_base,
        }
    }
}

/// Parent-side entry-frame snapshot used by `new_user_for_fork`.
/// Populated by `sys_fork` from the parent's live `PtRegs`.
#[derive(Copy, Clone, Default)]
pub struct ForkRegs {
    pub rdi: u64, pub rsi: u64, pub rdx: u64,
    pub r10: u64, pub r8:  u64, pub r9:  u64,
    pub rcx: u64, pub r11: u64,
    pub r12: u64,
    pub rbx: u64, pub rbp: u64,
    pub r13: u64, pub r14: u64, pub r15: u64,
}

#[cfg(test)]
mod tests;
