extern crate alloc;

use super::*;
use hal::Context;

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
        assert_eq!(ctx.r12, dummy_entry as *const () as usize as u64);
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

    /// Read the `PtRegs` a scaffold left at `ctx.rsp + 8`.
    /// # SAFETY: caller owns the backing stack buffer and `ctx` was just
    /// built on it, so the whole scaffold lies inside that allocation.
    unsafe fn scaffold_regs(ctx: &ContextX86_64) -> super::PtRegs {
        // SAFETY: per fn contract — `ctx.rsp` is the scaffold base inside a
        // live buffer; the frame starts one quadword above it.
        unsafe { *((ctx.rsp as usize + 8) as *const super::PtRegs) }
    }

    #[test]
    fn new_kernel_with_irq_frame_layout() {
        // `14§R07` pins the scaffold: saved-RIP + one `PtRegs`. The IRQ
        // epilogue pops all 15 GPRs, so entry/arg must be in the FRAME's
        // r12/r13 and not only in `Context` — otherwise the trampoline
        // jumps through a zeroed r12 on the task's first run.
        let mut stack = alloc::vec![0u8; 4096];
        let top = stack.as_mut_ptr_range().end;
        let ctx = ContextX86_64::new_kernel_with_irq_frame(top, dummy_entry, 0xC0FFEE);
        assert_eq!(ctx.r12, dummy_entry as *const () as usize as u64);
        assert_eq!(ctx.r13, 0xC0FFEE);
        // rsp = stack_top - (8 + sizeof(PtRegs)) = -184.
        assert_eq!(ctx.rsp as usize, (top as usize) - super::SCAFFOLD_BYTES);
        assert_eq!(super::SCAFFOLD_BYTES, 184);
        // `oxide_context_switch`'s `ret` must land 16-aligned so the
        // trampoline's `call oxide_finish_task_switch` is ABI-correct.
        assert_eq!((ctx.rsp as usize + 8) % 16, 0, "post-`ret` rsp must be 16-aligned");
        // SAFETY: we own `stack`; the scaffold lies inside the buffer.
        let slot = unsafe { *(ctx.rsp as *const u64) };
        assert_eq!(slot, finish_switch_tramp_addr(), "saved RIP for the switch `ret`");
        // SAFETY: same buffer; the frame starts at rsp+8.
        let r = unsafe { scaffold_regs(&ctx) };
        assert_eq!(r.r12, dummy_entry as *const () as usize as u64, "trampoline entry");
        assert_eq!(r.r13, 0xC0FFEE, "trampoline arg");
        assert_eq!(r.rax, 0); assert_eq!(r.rdi, 0); assert_eq!(r.rbx, 0);
        assert_eq!(r.error, 0, "no CPU error code on a synthetic frame");
        assert_eq!(r.vector, super::SCAFFOLD_VECTOR);
        assert!(!r.from_syscall(), "a kthread scaffold is not a syscall frame");
        assert_eq!(r.rip, super::trampoline_kernel_addr(), "iretq RIP");
        assert_eq!(r.cs, crate::idt::KERNEL_CS as u64, "iretq CS (Limine kernel code = 0x28)");
        assert!(!r.from_user(), "kthread stays at CPL 0");
        assert_eq!(r.rflags, 0x202,       "iretq RFLAGS (IF=1)");
        assert_eq!(r.rsp, top as u64,     "iretq RSP_post (= stack_top)");
        assert_eq!(r.ss, crate::gdt::KERNEL_DS as u64, "iretq SS (Limine kernel data = 0x30)");
    }

    #[test]
    fn new_user_with_irq_frame_returns_to_ring_three() {
        let mut stack = alloc::vec![0u8; 4096];
        let top = stack.as_mut_ptr_range().end;
        let ctx = ContextX86_64::new_user_with_irq_frame(top, 0x4000_1234, 0x7fff_0000);
        assert_eq!(ctx.rsp as usize, (top as usize) - super::SCAFFOLD_BYTES);
        // SAFETY: we own `stack`; the scaffold lies inside the buffer.
        let r = unsafe { scaffold_regs(&ctx) };
        assert_eq!(r.rip, 0x4000_1234);
        assert_eq!(r.rsp, 0x7fff_0000);
        assert_eq!(r.cs, crate::gdt::USER_CS_SELECTOR);
        assert_eq!(r.ss, crate::gdt::USER_SS_SELECTOR);
        assert!(r.from_user(), "iretq must land at CPL 3");
        assert_eq!(r.rflags & (1 << 9), 1 << 9, "user tasks start preemptible (IF=1)");
    }

    #[test]
    fn fork_scaffold_carries_every_callee_saved_reg_in_the_frame() {
        // The epilogue restores rbx/rbp/r12-r15 from the frame now, so a
        // child whose callee-saved state lived only in `Context` would
        // resume user mode with zeros in exactly the registers a compiled
        // `_start` keeps its loop invariants in.
        let mut stack = alloc::vec![0u8; 4096];
        let top = stack.as_mut_ptr_range().end;
        let regs = super::ForkRegs {
            rdi: 1, rsi: 2, rdx: 3, r10: 4, r8: 5, r9: 6,
            rcx: 7, r11: 8, r12: 12, rbx: 13, rbp: 14, r13: 15, r14: 16, r15: 17,
        };
        let ctx = ContextX86_64::new_user_for_fork(top, 0x4000_0000, 0x7fff_f000, 0x246, &regs, 0xfeed);
        // SAFETY: we own `stack`; the scaffold lies inside the buffer.
        let r = unsafe { scaffold_regs(&ctx) };
        assert_eq!((r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9), (1, 2, 3, 4, 5, 6));
        assert_eq!((r.rcx, r.r11), (7, 8));
        assert_eq!((r.r12, r.rbx, r.rbp, r.r13, r.r14, r.r15), (12, 13, 14, 15, 16, 17));
        assert_eq!(r.rax, 0, "child sees fork() == 0");
        assert_eq!(r.rflags, 0x246, "parent's RFLAGS carried through");
        assert!(r.from_user());
        assert_eq!(ctx.fs_base, 0xfeed, "parent TLS base inherited");
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
