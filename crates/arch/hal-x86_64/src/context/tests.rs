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

    #[test]
    fn new_kernel_with_irq_frame_layout() {
        // `14§R07` pins the 17-quadword scaffold layout. Walk every
        // slot from rsp upward; any reordering of the IRQ stub's
        // expectations breaks here loud.
        let mut stack = alloc::vec![0u8; 4096];
        let top = stack.as_mut_ptr_range().end;
        let ctx = ContextX86_64::new_kernel_with_irq_frame(top, dummy_entry, 0xC0FFEE);
        // r12/r13 carry entry/arg per trampoline ABI.
        assert_eq!(ctx.r12, dummy_entry as *const () as usize as u64);
        assert_eq!(ctx.r13, 0xC0FFEE);
        // rsp = stack_top - 136 (17 × 8).
        assert_eq!(ctx.rsp as usize, (top as usize) - 136);
        // Read the scaffold quadwords.
        // SAFETY: we own `stack`; rsp..rsp+136 lies inside the buffer.
        let read = |off: usize| -> u64 { unsafe { *((ctx.rsp as usize + off) as *const u64) } };
        assert_eq!(read(0x00), finish_switch_tramp_addr());
        for i in 0..9 { assert_eq!(read(0x08 + i * 8), 0, "scratch slot {} non-zero", i); }
        assert_eq!(read(0x50), 0,    "err pad");
        assert_eq!(read(0x58), 0x40, "vec pad");
        assert_eq!(read(0x60), super::trampoline_kernel_addr(), "iretq RIP");
        assert_eq!(read(0x68), crate::idt::KERNEL_CS as u64, "iretq CS (Limine kernel code = 0x28)");
        assert_eq!(read(0x70), 0x202,          "iretq RFLAGS (IF=1)");
        assert_eq!(read(0x78), top as u64,     "iretq RSP_post (= stack_top)");
        assert_eq!(read(0x80), 0x30,           "iretq SS (Limine kernel data = 0x30)");
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
