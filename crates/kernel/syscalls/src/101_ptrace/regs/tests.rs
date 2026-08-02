use super::*;

mod x86_tests {
    use super::x86;
    use hal_x86_64::{PtRegs, PT_REGS_VECTOR_SYSCALL};
    use syscall::errno::Errno;

    fn seg() -> x86::SegState {
        x86::SegState { ds: 0, es: 0, fs: 0, gs: 0,
                        fs_base: 0x7f00_0000_0000, gs_base: 0 }
    }

    /// Every field holds a distinct value so a wrong mapping shows as a wrong
    /// value rather than a coincidence. `vector` tags a `syscall` entry.
    fn frame() -> PtRegs {
        PtRegs {
            r15: 0xA015, r14: 0xA014, r13: 0xA013, r12: 0xA012,
            rbp: 0xA0B0, rbx: 0xA0B1,
            r11: 0xA011, r10: 0xA010, r9: 0xA009, r8: 0xA008,
            rdi: 0xA0D1, rsi: 0xA051, rdx: 0xA0D2, rcx: 0xA0C1,
            rax: 0xA0A0,
            vector: PT_REGS_VECTOR_SYSCALL, error: 0,
            rip: 0xA1B0, cs: 0x4b, rflags: 0xA1F0, rsp: 0xA150, ss: 0x43,
        }
    }

    /// A trap frame: no `syscall` instruction built it.
    fn trap_frame() -> PtRegs {
        PtRegs { vector: 14, ..frame() }
    }

    #[test]
    fn x86_user_regs_struct_is_27_quadwords() {
        assert_eq!(x86::N, 27);
        assert_eq!(x86::N * 8, 216);
    }

    /// The whole point of the item this test pins: `rip` must be the frame's
    /// `rip`, not its `rcx`, and `orig_rax` the syscall number, not `r11`.
    /// A stale 16-quadword frame model read exactly those two swapped.
    #[test]
    fn x86_frame_maps_onto_the_right_user_regs_fields() {
        let f = frame();
        let u = x86::to_user_regs(&f, 0x1234, &seg());
        assert_eq!(u[x86::U_R15], f.r15);
        assert_eq!(u[x86::U_R14], f.r14);
        assert_eq!(u[x86::U_R13], f.r13);
        assert_eq!(u[x86::U_R12], f.r12);
        assert_eq!(u[x86::U_RBP], f.rbp);
        assert_eq!(u[x86::U_RBX], f.rbx);
        assert_eq!(u[x86::U_R11], f.r11);
        assert_eq!(u[x86::U_R10], f.r10);
        assert_eq!(u[x86::U_R9],  f.r9);
        assert_eq!(u[x86::U_R8],  f.r8);
        assert_eq!(u[x86::U_RCX], f.rcx);
        assert_eq!(u[x86::U_RDX], f.rdx);
        assert_eq!(u[x86::U_RSI], f.rsi);
        assert_eq!(u[x86::U_RDI], f.rdi);
        assert_eq!(u[x86::U_RIP], f.rip, "rip must not come from rcx");
        assert_eq!(u[x86::U_RSP], f.rsp);
        assert_eq!(u[x86::U_EFLAGS], f.rflags);
        assert_eq!(u[x86::U_ORIG_RAX], f.rax, "orig_rax must not come from r11");
        assert_eq!(u[x86::U_RAX], 0x1234, "the stop's return register");
        assert_eq!(u[x86::U_CS], f.cs, "cs comes from the frame, not a fixed selector");
        assert_eq!(u[x86::U_SS], f.ss);
        assert_eq!(u[x86::U_FS_BASE], 0x7f00_0000_0000);
        // Distinct fields must not alias: rip/rcx and eflags/r11 are separate
        // registers on this frame, which the pre-fix model conflated.
        assert_ne!(u[x86::U_RIP], u[x86::U_RCX]);
        assert_ne!(u[x86::U_EFLAGS], u[x86::U_R11]);
    }

    /// A trap frame has no syscall: `orig_rax` reads back as the no-syscall
    /// marker and `rax` is the thread's own register, matching the register
    /// block a core dump writes for the same frame.
    #[test]
    fn x86_trap_frame_reports_no_syscall_and_the_architectural_rax() {
        let f = trap_frame();
        let u = x86::to_user_regs(&f, 0xDEAD, &seg());
        assert_eq!(u[x86::U_ORIG_RAX], x86::NO_SYSCALL);
        assert_eq!(u[x86::U_RAX], f.rax);
    }

    #[test]
    fn x86_round_trip_preserves_every_general_register() {
        let f0 = frame();
        let mut s = seg();
        let u = x86::to_user_regs(&f0, 0x1234, &s);
        let mut f1 = PtRegs { vector: PT_REGS_VECTOR_SYSCALL, rflags: 0x200, ..Default::default() };
        let rax = x86::from_user_regs(&u, &mut f1, &mut s, 0x0000_8000_0000_0000).unwrap();
        assert_eq!(rax, 0x1234);
        assert_eq!(f1.r15, f0.r15);
        assert_eq!(f1.r14, f0.r14);
        assert_eq!(f1.r13, f0.r13);
        assert_eq!(f1.r12, f0.r12);
        assert_eq!(f1.rbp, f0.rbp);
        assert_eq!(f1.rbx, f0.rbx);
        assert_eq!(f1.r11, f0.r11);
        assert_eq!(f1.r10, f0.r10);
        assert_eq!(f1.r9,  f0.r9);
        assert_eq!(f1.r8,  f0.r8);
        assert_eq!(f1.rdi, f0.rdi);
        assert_eq!(f1.rsi, f0.rsi);
        assert_eq!(f1.rdx, f0.rdx);
        assert_eq!(f1.rcx, f0.rcx);
        assert_eq!(f1.rip, f0.rip);
        assert_eq!(f1.rsp, f0.rsp);
        assert_eq!(f1.rax, f0.rax, "the syscall number survives a round trip");
    }

    #[test]
    fn x86_setregs_on_a_trap_frame_installs_the_architectural_rax() {
        let mut f = trap_frame();
        let mut s = seg();
        let mut u = [0u64; x86::N];
        u[x86::U_CS] = 0x4b; u[x86::U_SS] = 0x43;
        u[x86::U_RAX] = 0x5150;
        u[x86::U_ORIG_RAX] = x86::NO_SYSCALL;
        x86::from_user_regs(&u, &mut f, &mut s, 0x0000_8000_0000_0000).unwrap();
        assert_eq!(f.rax, 0x5150, "a trap frame's rax must not become -1");
    }

    #[test]
    fn x86_setregs_cannot_clear_the_interrupt_flag() {
        let mut f = PtRegs { rflags: 0x202, ..Default::default() }; // IF | reserved
        let mut s = seg();
        let mut u = [0u64; x86::N];
        u[x86::U_CS] = 0x4b; u[x86::U_SS] = 0x43;
        u[x86::U_EFLAGS] = 0x101; // CF | TF, IF clear
        x86::from_user_regs(&u, &mut f, &mut s, 0x0000_8000_0000_0000).unwrap();
        assert_eq!(f.rflags & 0x200, 0x200, "IF must be preserved");
        assert_eq!(f.rflags & 0x101, 0x101, "CF|TF must be installed");
    }

    #[test]
    fn x86_setregs_rejects_a_ring0_selector() {
        let mut f = PtRegs::default();
        let mut s = seg();
        let mut u = [0u64; x86::N];
        u[x86::U_CS] = 0x08; // RPL 0
        assert_eq!(x86::from_user_regs(&u, &mut f, &mut s, 0x0000_8000_0000_0000),
                   Err(Errno::Eio));
        // Zero is explicitly allowed (Linux `invalid_selector`).
        u[x86::U_CS] = 0;
        assert!(x86::from_user_regs(&u, &mut f, &mut s, 0x0000_8000_0000_0000).is_ok());
    }

    #[test]
    fn x86_setregs_rejects_a_kernel_fs_base() {
        let mut f = PtRegs::default();
        let mut s = seg();
        let mut u = [0u64; x86::N];
        u[x86::U_FS_BASE] = 0xffff_8000_0000_0000;
        assert_eq!(x86::from_user_regs(&u, &mut f, &mut s, 0x0000_8000_0000_0000),
                   Err(Errno::Eio));
        u[x86::U_FS_BASE] = 0;
        u[x86::U_GS_BASE] = 0xffff_ffff_8000_0000;
        assert_eq!(x86::from_user_regs(&u, &mut f, &mut s, 0x0000_8000_0000_0000),
                   Err(Errno::Eio));
    }

    /// The frame the tracer reads is the frame the entry asm pushes, at the
    /// address derived from that struct's own size. Pinning both here is what
    /// makes the pre-fix `16 quadwords at top - 0x80` unrepresentable.
    #[test]
    fn x86_entry_frame_is_22_quadwords() {
        assert_eq!(core::mem::size_of::<PtRegs>(), 22 * 8);
        assert_eq!(core::mem::size_of::<PtRegs>(), 0xb0);
    }
}

mod arm64_tests {
    use super::arm64;
    use hal_aarch64::SvcFrame;

    fn arm_frame() -> SvcFrame {
        let mut gp = [0u64; 18];
        for (i, w) in gp.iter_mut().enumerate() { *w = 0xB000 + i as u64 }
        let mut x19_x28 = [0u64; 10];
        for (i, w) in x19_x28.iter_mut().enumerate() { *w = 0xB100 + i as u64 }
        SvcFrame {
            gp,
            x18_x29: [0xB018, 0xB029],
            x30: 0xB030,
            _pad_x30: 0,
            elr_el1: 0xB0E1,
            spsr_el1: 0, // valid EL0t
            sp_el0: 0xB050,
            retval: 0xB0FF,
            x19_x28,
        }
    }

    #[test]
    fn arm64_user_pt_regs_is_34_quadwords() {
        assert_eq!(arm64::N, 34);
        assert_eq!(arm64::N * 8, 272);
    }

    /// `SvcFrame` scatters x18/x29 into a packed pair and parks x19..x28 after
    /// the exception state; `user_pt_regs` wants a flat x0..x30.
    #[test]
    fn arm64_scattered_frame_flattens_to_x0_through_x30() {
        let f = arm_frame();
        let u = arm64::to_user_pt_regs(&f, 0xC0DE);
        assert_eq!(u[0], 0xC0DE, "x0 comes from the caller-supplied value");
        for i in 1..18 { assert_eq!(u[i], f.gp[i], "x{i}"); }
        assert_eq!(u[18], f.x18_x29[0]);
        for i in 19..=28 { assert_eq!(u[i], f.x19_x28[i - 19], "x{i}"); }
        assert_eq!(u[29], f.x18_x29[1]);
        assert_eq!(u[30], f.x30);
        assert_eq!(u[arm64::U_SP], f.sp_el0);
        assert_eq!(u[arm64::U_PC], f.elr_el1);
        assert_eq!(u[arm64::U_PSTATE], f.spsr_el1);
    }

    #[test]
    fn arm64_round_trip_preserves_every_register() {
        let f0 = arm_frame();
        let u = arm64::to_user_pt_regs(&f0, f0.gp[0]);
        let mut f1 = arm_frame();
        f1.gp = [0u64; 18];
        f1.x18_x29 = [0; 2];
        f1.x30 = 0;
        f1.x19_x28 = [0u64; 10];
        f1.sp_el0 = 0; f1.elr_el1 = 0; f1.retval = 0;
        arm64::from_user_pt_regs(&u, &mut f1);
        assert_eq!(f1.gp, f0.gp);
        assert_eq!(f1.x18_x29, f0.x18_x29);
        assert_eq!(f1.x19_x28, f0.x19_x28);
        assert_eq!(f1.x30, f0.x30);
        assert_eq!(f1.sp_el0, f0.sp_el0);
        assert_eq!(f1.elr_el1, f0.elr_el1);
        assert_eq!(f1.retval, f0.gp[0]);
    }

    #[test]
    fn arm64_setregs_cannot_promote_the_exception_level() {
        // EL1h (mode 0x5) with interrupts masked — must collapse to NZCV only.
        let dirty = 0x8000_0000 | 0x3c5;
        assert_eq!(arm64::sanitize_pstate(dirty), 0x8000_0000);
        // Clean EL0t with condition flags survives untouched.
        assert_eq!(arm64::sanitize_pstate(0xF000_0000), 0xF000_0000);
        // AArch32 state bit is rejected too.
        assert_eq!(arm64::sanitize_pstate(arm64::PSR_MODE32_BIT), 0);
        // Any DAIF mask bit is rejected.
        for b in [arm64::PSR_D_BIT, arm64::PSR_A_BIT, arm64::PSR_I_BIT, arm64::PSR_F_BIT] {
            assert_eq!(arm64::sanitize_pstate(b), 0, "bit {b:#x}");
        }
    }

    /// Same pin as the x86 sibling: the frame the tracer reads is the frame
    /// the EL0-sync save block reserves, and its base is derived from this.
    #[test]
    fn arm64_entry_frame_is_36_quadwords() {
        assert_eq!(core::mem::size_of::<SvcFrame>(), 36 * 8);
        assert_eq!(core::mem::size_of::<SvcFrame>(), 0x120);
    }
}
