// x86_64 `Context` impl per `14§5`. The single asm symbol
// `oxide_context_switch` lives here (gated to the kernel target);
// host builds substitute a no-op extern fn so call-site checks
// exercise the trait surface without invoking real asm.
//
// Layout per `14§5.2`: 8 callee-saved + fs_base, repr(C), 64 B total.
// Offsets are asm-coupled — the inline assembly references `[rdi +
// 0x00]`, `[rsi + 0x00]`, etc. — so any field reordering breaks the
// switch. Tests pin every offset.

use hal::Context;

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
    pub fs_base: u64, // 0x38 (saved/restored by syscall entry, not switch)
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
    "    mov  ecx, 0xC0000100",
    "    wrmsr",
    "    ret",
    ".size oxide_context_switch, . - oxide_context_switch",
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
        }
    }

    /// Build a kernel-thread context whose saved kernel stack
    /// carries a synthetic IRQ frame matching the layout the IRQ
    /// epilogue (`oxide_irq_resume_user`) expects. Lets the IRQ
    /// dispatcher tail `Context::switch` directly into a fresh task
    /// and `iretq` from the same epilogue. Layout pinned in
    /// `14§R07`; total scaffold = 17 × 8 = 136 B starting at
    /// `Context.rsp`, growing toward `stack_top`:
    ///
    ///   [rsp+0x00]  saved RIP = oxide_irq_resume_user
    ///   [rsp+0x08..0x50]  saved scratch r11..rax (9×8, zero)
    ///   [rsp+0x50]  err = 0
    ///   [rsp+0x58]  vec = 0x40
    ///   [rsp+0x60]  iretq RIP = oxide_trampoline_kernel
    ///   [rsp+0x68]  iretq CS  = `KERNEL_CS` (0x28 — Limine GDT 64-bit code)
    ///   [rsp+0x70]  iretq RFL = 0x202 (IF=1, reserved bit 1)
    ///   [rsp+0x78]  iretq RSP = stack_top (post-iretq RSP — kthread
    ///               runs with the entire stack below stack_top)
    ///   [rsp+0x80]  iretq SS  = `KERNEL_DS` (0x30 — Limine GDT 64-bit data)
    ///
    /// `r12 = entry`, `r13 = arg` per the trampoline ABI; iretq
    /// preserves r12..r15 so the trampoline reads them correctly
    /// after iretq lands.
    ///
    /// # C: O(1)
    fn new_kernel_with_irq_frame(
        stack_top: *mut u8,
        entry: extern "C" fn(usize) -> !,
        arg: usize,
    ) -> Self {
        // SAFETY: caller asserts `stack_top` is the high end of a
        // writable, 16-byte-aligned kernel stack of at least 136 B.
        // We write 17 quadwords below stack_top in the layout above.
        let sp = unsafe {
            let p = stack_top.cast::<u64>();
            // iretq frame (offsets 0x60..0x80 from final rsp).
            // Selectors per Limine v6+ GDT layout: code = 0x28
            // (64-bit kernel CS), data = 0x30 (64-bit kernel DS/SS).
            p.sub(1).write(0x30);                        // SS  (kernel data)
            p.sub(2).write(stack_top as u64);            // RSP_post
            p.sub(3).write(0x202);                       // RFLAGS, IF=1
            p.sub(4).write(crate::idt::KERNEL_CS as u64); // CS  (kernel code)
            p.sub(5).write(trampoline_kernel_addr());    // RIP
            // synthetic vec/err pad (matches IRQ stub `push 0; push 0x40`).
            p.sub(6).write(0x40);                        // vec
            p.sub(7).write(0);                           // err
            // 9 scratch slots r11..rax — values irrelevant (popped + discarded).
            for i in 8..=16 { p.sub(i).write(0); }
            // saved RIP for oxide_context_switch's `ret`: the finish_switch
            // trampoline pays the switch handoff, then jmps the epilogue.
            p.sub(17).write(finish_switch_tramp_addr());
            p.sub(17)
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
            // SAFETY: rdmsr/wrmsr IA32_FS_BASE legal at CPL=0; reads/writes only the FS_BASE MSR.
            let cur_fs: u64 = unsafe {
                let lo: u32; let hi: u32;
                core::arch::asm!(
                    "rdmsr",
                    in("ecx") 0xC000_0100u32,
                    out("eax") lo, out("edx") hi,
                    options(nomem, nostack, preserves_flags),
                );
                ((hi as u64) << 32) | (lo as u64)
            };
            // SAFETY: prev is a valid &mut Self per fn contract.
            unsafe { (*prev).fs_base = cur_fs; }
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
            // SAFETY: prev is a valid *mut Self per fn contract; wrmsr IA32_FS_BASE legal at CPL=0.
            unsafe {
                let fs = (*prev).fs_base;
                let lo = fs as u32;
                let hi = (fs >> 32) as u32;
                core::arch::asm!(
                    "wrmsr",
                    in("ecx") 0xC000_0100u32,
                    in("eax") lo, in("edx") hi,
                    options(nomem, nostack, preserves_flags),
                );
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
    /// IRQ frame uses USER selectors (DPL=3) and `iretq` therefore
    /// transitions to ring 3 with CS=`USER_CS`, SS=`USER_DS`, RIP=
    /// `user_ip`, RSP=`user_sp`. RFLAGS=0x202 (IF=1, reserved bit 1)
    /// so user tasks are preemptible by the LAPIC timer. Ring-3 can
    /// neither sti nor cli (IOPL=0), so the IF state baked into the
    /// iretq frame is what user runs with for its lifetime.
    ///
    /// Layout matches the kernel-mode flavor — same scratch + vec/err
    /// + iretq frame shape — so the shared `oxide_irq_resume_user`
    /// epilogue iretq's into ring 3 instead of staying at CPL=0.
    /// Inherent on `ContextX86_64` (not on the `hal::Context` trait):
    /// arm parity rides a follow-up that adds sp_el0 save/restore to
    /// the IRQ frame.
    /// # C: O(1)
    pub fn new_user_with_irq_frame(stack_top: *mut u8, user_ip: u64, user_sp: u64) -> Self {
        // SAFETY: caller asserts `stack_top` is the high end of a
        // writable, 16-byte-aligned kernel stack of at least 136 B.
        let sp = unsafe {
            let p = stack_top.cast::<u64>();
            // iretq frame (offsets 0x60..0x80 from final rsp). USER
            // CS/SS per `36-bootloader-handoff` GDT (P1-93): USER_CS
            // = 0x4B (DPL=3 64-bit code), USER_DS = 0x43 (DPL=3 data).
            p.sub(1).write(crate::gdt::USER_DS as u64);     // SS  (user data)
            p.sub(2).write(user_sp);                         // RSP (user stack)
            p.sub(3).write(0x202);                           // RFLAGS, IF=1
            p.sub(4).write(crate::gdt::USER_CS as u64);     // CS  (user code)
            p.sub(5).write(user_ip);                         // RIP (user entry)
            // synthetic vec/err pad (matches IRQ stub layout).
            p.sub(6).write(0);                               // vec
            p.sub(7).write(0);                               // err
            // 9 scratch slots r11..rax — values irrelevant.
            for i in 8..=16 { p.sub(i).write(0); }
            // saved RIP for oxide_context_switch's `ret`: finish_switch
            // trampoline pays the handoff, then the shared epilogue iretq's
            // the frame above.
            p.sub(17).write(finish_switch_tramp_addr());
            p.sub(17)
        };
        Self {
            rsp: sp as u64,
            rbp: 0,
            rbx: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            fs_base: 0,
        }
    }

    /// Fork-specific user-task scaffold (P5-10): builds the same
    /// iretq frame as `new_user_with_irq_frame` but populates the 9
    /// scratch slots (r11..rax) and the Context callee-saved fields
    /// (rbx/rbp/r13/r14/r15) from the parent's saved-syscall block,
    /// so the child resumes user mode with the exact same register
    /// state — except `rax` is overwritten to 0 (the fork return
    /// value the child sees).
    ///
    /// `regs` layout matches `current_user_full_frame()` — see
    /// `crates/hal-x86_64::syscall::current_user_full_frame` for
    /// offsets. user_ip/user_sp are passed separately because the
    /// caller already pulls them from `current_user_frame()`.
    ///
    /// Note: user `r12` is unrecoverable (the syscall asm clobbers
    /// it before any save) — the slot in `regs` here is the parent's
    /// saved-stack slot which actually holds user RSP. `r12` is now
    /// preserved (was zeroed pre-B04; broke compiled C `_start` that
    /// loaded loop-invariant pointers into r12).
    /// # C: O(1)
    pub fn new_user_for_fork(
        stack_top: *mut u8,
        user_ip: u64,
        user_sp: u64,
        user_rflags: u64,
        regs: &ForkRegs,
        parent_fs_base: u64,
    ) -> Self {
        // SAFETY: same as `new_user_with_irq_frame`.
        let sp = unsafe {
            let p = stack_top.cast::<u64>();
            p.sub(1).write(crate::gdt::USER_DS as u64);
            p.sub(2).write(user_sp);
            p.sub(3).write(user_rflags);
            p.sub(4).write(crate::gdt::USER_CS as u64);
            p.sub(5).write(user_ip);
            p.sub(6).write(0);                               // vec
            p.sub(7).write(0);                               // err
            // Scratch slots, popped low→high by oxide_irq_resume_user
            // in this order: r11, r10, r9, r8, rdi, rsi, rdx, rcx, rax.
            // Stack-wise: sub(16) = r11 (lowest), sub(8) = rax (highest).
            p.sub(16).write(regs.r11);
            p.sub(15).write(regs.r10);
            p.sub(14).write(regs.r9);
            p.sub(13).write(regs.r8);
            p.sub(12).write(regs.rdi);
            p.sub(11).write(regs.rsi);
            p.sub(10).write(regs.rdx);
            p.sub(9).write(regs.rcx);
            p.sub(8).write(0);                               // rax = 0 (child's fork return)
            p.sub(17).write(finish_switch_tramp_addr());
            p.sub(17)
        };
        Self {
            rsp: sp as u64,
            rbp: regs.rbp,
            rbx: regs.rbx,
            r12: regs.r12,
            r13: regs.r13,
            r14: regs.r14,
            r15: regs.r15,
            fs_base: parent_fs_base,
        }
    }
}

/// Parent-side syscall-frame snapshot used by `new_user_for_fork`.
/// Populated by `sys_fork` from the saved-syscall block.
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
