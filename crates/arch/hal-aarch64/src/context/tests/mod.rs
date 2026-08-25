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
    assert_eq!(ctx.x19, dummy_entry as *const () as usize as u64);
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
fn new_kernel_with_irq_frame_layout() {
    // `14§6.5` pins the full 288-byte on-stack scaffold.
    // Walk every slot from sp upward; any reorder of the IRQ
    // stub's expectations breaks here loud.
    let mut stack = alloc::vec![0u8; 4096];
    let top = stack.as_mut_ptr_range().end;
    let ctx = ContextAArch64::new_kernel_with_irq_frame(top, dummy_entry, 0xC0FFEE);
    assert_eq!(ctx.x19, dummy_entry as *const () as usize as u64);
    assert_eq!(ctx.x20, 0xC0FFEE);
    assert_eq!(ctx.sp as usize, (top as usize) - 288);
    assert_eq!(ctx.lr,  finish_switch_tramp_addr());
    // SAFETY: we own `stack`; sp..sp+288 lies inside the buffer.
    let read = |off: usize| -> u64 { unsafe { *((ctx.sp as usize + off) as *const u64) } };
    for i in 0..22 { assert_eq!(read(i * 8), 0, "GP slot {} non-zero", i); }
    assert_eq!(read(0xb0), super::trampoline_kernel_addr(), "saved ELR_EL1");
    assert_eq!(read(0xb8), 0x145,                            "saved SPSR_EL1");
    assert_eq!(read(0xc0), 0,                                "saved sp_el0 (kthread)");
    assert_eq!(read(0xd0), dummy_entry as *const () as usize as u64, "saved x19");
    assert_eq!(read(0xd8), 0xC0FFEE, "saved x20");
    for i in 0..8 { assert_eq!(read(0xe0 + i * 8), 0, "saved x{}", 21 + i); }
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
