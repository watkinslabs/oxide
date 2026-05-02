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
    ".intel_syntax noprefix",
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
    "    ret",
    ".size oxide_context_switch, . - oxide_context_switch",
);

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
core::arch::global_asm!(
    ".intel_syntax noprefix",
    ".section .text",
    ".globl oxide_trampoline_kernel",
    ".type  oxide_trampoline_kernel, @function",
    "oxide_trampoline_kernel:",
    "    mov rdi, r13",
    "    jmp r12",
    ".size oxide_trampoline_kernel, . - oxide_trampoline_kernel",
);

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
extern "C" {
    fn oxide_context_switch(prev: *mut ContextX86_64, next: *const ContextX86_64);
    fn oxide_trampoline_kernel() -> !;
}

/// Kernel-target trampoline address; host build returns 0 since
/// `Context::switch` is a no-op there anyway.
fn trampoline_kernel_addr() -> u64 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { oxide_trampoline_kernel as usize as u64 }
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
            r12: entry as usize as u64,
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
            // SAFETY: defers to `oxide_context_switch` whose preconditions
            // mirror this fn's; the asm preserves only the SysV
            // callee-saved set — caller must hold runqueue lock and
            // have preempt disabled, per the trait contract above.
            unsafe { oxide_context_switch(prev, next); }
        }
        #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
        {
            // Host fallback: no real switch on the host CPU; just
            // touch the pointers so the borrow-checker sees them.
            let _ = (prev, next);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_offsets_match_asm() {
        // `14§5.2` pins these offsets — asm uses `[rdi + 0xNN]`. Any
        // reordering breaks the switch.
        assert_eq!(core::mem::offset_of!(ContextX86_64, rsp),     0x00);
        assert_eq!(core::mem::offset_of!(ContextX86_64, rbp),     0x08);
        assert_eq!(core::mem::offset_of!(ContextX86_64, rbx),     0x10);
        assert_eq!(core::mem::offset_of!(ContextX86_64, r12),     0x18);
        assert_eq!(core::mem::offset_of!(ContextX86_64, r13),     0x20);
        assert_eq!(core::mem::offset_of!(ContextX86_64, r14),     0x28);
        assert_eq!(core::mem::offset_of!(ContextX86_64, r15),     0x30);
        assert_eq!(core::mem::offset_of!(ContextX86_64, fs_base), 0x38);
        assert_eq!(core::mem::size_of::<ContextX86_64>(), 0x40);
    }

    extern "C" fn dummy_entry(_arg: usize) -> ! { loop {} }

    #[test]
    fn new_kernel_stages_entry_and_arg() {
        let mut stack = alloc::vec![0u8; 4096];
        // Take stack_top = end of buffer (high address).
        let top = stack.as_mut_ptr_range().end;
        let ctx = ContextX86_64::new_kernel(top, dummy_entry, 0xDEAD_BEEF);
        assert_eq!(ctx.r12, dummy_entry as usize as u64);
        assert_eq!(ctx.r13, 0xDEAD_BEEF);
        // rsp lives one u64 below stack_top after we pushed the trampoline.
        let expected_sp = (top as usize) - 8;
        assert_eq!(ctx.rsp as usize, expected_sp);
        // The slot at rsp holds the trampoline-return address.
        // SAFETY: we own `stack`; rsp points 8 bytes below `top`,
        // inside the buffer.
        let slot = unsafe { *(ctx.rsp as *const u64) };
        assert_eq!(slot, trampoline_kernel_addr());
    }

    #[test]
    fn new_user_stages_user_ip_and_sp() {
        let mut stack = alloc::vec![0u8; 256];
        let top = stack.as_mut_ptr_range().end;
        let ctx = ContextX86_64::new_user(top, 0x4000_1234, 0x7fff_aaaa);
        assert_eq!(ctx.r14, 0x4000_1234, "user_ip parked in r14");
        assert_eq!(ctx.r13, 0x7fff_aaaa, "user_sp parked in r13");
        assert_eq!(ctx.rsp, top as u64);
    }

    #[test]
    fn switch_host_fallback_compiles_and_returns() {
        let mut prev = ContextX86_64::default();
        let next = ContextX86_64::default();
        // SAFETY: host fallback is a no-op; pointers don't need to
        // satisfy the kernel-target preconditions because the asm
        // path is cfg'd out on this build.
        unsafe { ContextX86_64::switch(&mut prev as *mut _, &next as *const _); }
    }
}

#[cfg(test)]
extern crate alloc;
