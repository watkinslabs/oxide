// aarch64 `Context` impl per `14§6`. Single asm symbol
// `oxide_context_switch` lives here, gated to the kernel target;
// host builds substitute a no-op so trait surface is exercisable.
//
// Layout per `14§6.2`: sp + x19..x29 + lr (x30) + tpidr (user TLS),
// repr(C), 14 slots × 8 = 112 B. Offsets are asm-coupled; tests
// pin every field.

use hal::Context;

/// Saved kernel-state register set per `14§6.2`. Field order is
/// asm-coupled; do not reorder.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct ContextAArch64 {
    pub sp:    u64, // 0x00
    pub x19:   u64, // 0x08 — trampoline reads `entry` from here
    pub x20:   u64, // 0x10 — trampoline reads `arg` from here
    pub x21:   u64, // 0x18
    pub x22:   u64, // 0x20
    pub x23:   u64, // 0x28
    pub x24:   u64, // 0x30
    pub x25:   u64, // 0x38
    pub x26:   u64, // 0x40
    pub x27:   u64, // 0x48
    pub x28:   u64, // 0x50
    pub x29:   u64, // 0x58 — frame pointer
    pub lr:    u64, // 0x60 — x30
    pub tpidr: u64, // 0x68 — user TLS base (saved by syscall entry)
}

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
core::arch::global_asm!(
    ".section .text",
    ".globl oxide_context_switch",
    ".type  oxide_context_switch, %function",
    "oxide_context_switch:",
    "    mov  x9, sp",
    "    str  x9,         [x0, #0x00]",
    "    stp  x19, x20,   [x0, #0x08]",
    "    stp  x21, x22,   [x0, #0x18]",
    "    stp  x23, x24,   [x0, #0x28]",
    "    stp  x25, x26,   [x0, #0x38]",
    "    stp  x27, x28,   [x0, #0x48]",
    "    stp  x29, x30,   [x0, #0x58]",
    "    ldr  x9,         [x1, #0x00]",
    "    mov  sp, x9",
    "    ldp  x19, x20,   [x1, #0x08]",
    "    ldp  x21, x22,   [x1, #0x18]",
    "    ldp  x23, x24,   [x1, #0x28]",
    "    ldp  x25, x26,   [x1, #0x38]",
    "    ldp  x27, x28,   [x1, #0x48]",
    "    ldp  x29, x30,   [x1, #0x58]",
    "    ret",
    ".size oxide_context_switch, . - oxide_context_switch",
);

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
core::arch::global_asm!(
    ".section .text",
    ".globl oxide_trampoline_kernel",
    ".type  oxide_trampoline_kernel, %function",
    "oxide_trampoline_kernel:",
    "    mov x0, x20",
    "    br  x19",
    ".size oxide_trampoline_kernel, . - oxide_trampoline_kernel",
);

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
extern "C" {
    fn oxide_context_switch(prev: *mut ContextAArch64, next: *const ContextAArch64);
    fn oxide_trampoline_kernel() -> !;
}

fn trampoline_kernel_addr() -> u64 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { oxide_trampoline_kernel as usize as u64 }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { 0 }
}

impl Context for ContextAArch64 {
    /// Build a kernel-thread context that, on first `switch`-to,
    /// returns into `oxide_trampoline_kernel` (lr loaded from `lr`
    /// field). The trampoline reads `entry` from `x19` and `arg`
    /// from `x20` and tail-branches to `entry(arg)`.
    /// # C: O(1)
    fn new_kernel(stack_top: *mut u8, entry: extern "C" fn(usize) -> !, arg: usize) -> Self {
        Self {
            sp:    stack_top as u64,
            x19:   entry as usize as u64,
            x20:   arg as u64,
            x21: 0, x22: 0, x23: 0, x24: 0,
            x25: 0, x26: 0, x27: 0, x28: 0,
            x29: 0,
            lr:    trampoline_kernel_addr(),
            tpidr: 0,
        }
    }

    /// Build a context for first-entry into user-mode. The actual
    /// `eret` to EL0 happens in the syscall/IRQ-exit asm in `21§*` —
    /// this stages user_ip in x19 and user_sp in x20 for the user
    /// trampoline.
    /// # C: O(1)
    fn new_user(stack_top: *mut u8, user_ip: u64, user_sp: u64) -> Self {
        Self {
            sp:    stack_top as u64,
            x19:   user_ip,
            x20:   user_sp,
            x21: 0, x22: 0, x23: 0, x24: 0,
            x25: 0, x26: 0, x27: 0, x28: 0,
            x29: 0,
            lr: 0,
            tpidr: 0,
        }
    }

    /// # SAFETY: `prev` and `next` reference valid `Context` records;
    /// `next`'s saved stack is a valid kernel stack with the
    /// trampoline (or a frame from a prior switch) at `lr`; preempt
    /// disabled; runqueue lock held by caller and released by the
    /// next thread post-switch per `14§4`.
    /// # C: O(1)
    /// # Ctx: process|irq-return path; preempt-off
    unsafe fn switch(prev: *mut Self, next: *const Self) {
        #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
        {
            // SAFETY: defers to `oxide_context_switch`; the asm
            // preserves only the AAPCS64 callee-saved set per
            // `14§6.1`. Caller satisfies the trait contract above.
            unsafe { oxide_context_switch(prev, next); }
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
        {
            let _ = (prev, next);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_offsets_match_asm() {
        // `14§6.2` pins these — asm uses `[x0, #0xNN]`.
        assert_eq!(core::mem::offset_of!(ContextAArch64, sp),    0x00);
        assert_eq!(core::mem::offset_of!(ContextAArch64, x19),   0x08);
        assert_eq!(core::mem::offset_of!(ContextAArch64, x20),   0x10);
        assert_eq!(core::mem::offset_of!(ContextAArch64, x21),   0x18);
        assert_eq!(core::mem::offset_of!(ContextAArch64, x22),   0x20);
        assert_eq!(core::mem::offset_of!(ContextAArch64, x23),   0x28);
        assert_eq!(core::mem::offset_of!(ContextAArch64, x24),   0x30);
        assert_eq!(core::mem::offset_of!(ContextAArch64, x25),   0x38);
        assert_eq!(core::mem::offset_of!(ContextAArch64, x26),   0x40);
        assert_eq!(core::mem::offset_of!(ContextAArch64, x27),   0x48);
        assert_eq!(core::mem::offset_of!(ContextAArch64, x28),   0x50);
        assert_eq!(core::mem::offset_of!(ContextAArch64, x29),   0x58);
        assert_eq!(core::mem::offset_of!(ContextAArch64, lr),    0x60);
        assert_eq!(core::mem::offset_of!(ContextAArch64, tpidr), 0x68);
        assert_eq!(core::mem::size_of::<ContextAArch64>(), 0x70);
    }

    extern "C" fn dummy_entry(_arg: usize) -> ! { loop {} }

    #[test]
    fn new_kernel_stages_entry_and_arg() {
        let mut stack = alloc::vec![0u8; 4096];
        let top = stack.as_mut_ptr_range().end;
        let ctx = ContextAArch64::new_kernel(top, dummy_entry, 0xCAFE_F00D);
        assert_eq!(ctx.x19, dummy_entry as usize as u64);
        assert_eq!(ctx.x20, 0xCAFE_F00D);
        assert_eq!(ctx.sp, top as u64);
        assert_eq!(ctx.lr, trampoline_kernel_addr());
    }

    #[test]
    fn new_user_stages_user_ip_and_sp() {
        let mut stack = alloc::vec![0u8; 256];
        let top = stack.as_mut_ptr_range().end;
        let ctx = ContextAArch64::new_user(top, 0x4000_1234, 0x7fff_aaaa);
        assert_eq!(ctx.x19, 0x4000_1234);
        assert_eq!(ctx.x20, 0x7fff_aaaa);
        assert_eq!(ctx.sp,  top as u64);
    }

    #[test]
    fn switch_host_fallback_compiles_and_returns() {
        let mut prev = ContextAArch64::default();
        let next = ContextAArch64::default();
        // SAFETY: host fallback is a no-op; pointers don't need to
        // satisfy kernel-target preconditions because asm is cfg'd
        // out on this build.
        unsafe { ContextAArch64::switch(&mut prev as *mut _, &next as *const _); }
    }
}

#[cfg(test)]
extern crate alloc;
