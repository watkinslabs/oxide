use super::*;

fn seg() -> x86::SegState {
    x86::SegState { cs: 0x4b, ss: 0x43, ds: 0, es: 0, fs: 0, gs: 0,
                    fs_base: 0x7f00_0000_0000, gs_base: 0 }
}

/// Frame slot `i` holds `0xA000 + i` so a wrong index shows as a wrong value.
fn frame() -> [u64; x86::FRAME_N] {
    let mut f = [0u64; x86::FRAME_N];
    for i in 0..x86::FRAME_N { f[i] = 0xA000 + i as u64; }
    f
}

#[test]
fn x86_user_regs_struct_is_27_quadwords() {
    assert_eq!(x86::N, 27);
    assert_eq!(x86::N * 8, 216);
}

/// The pre-fix shim copied the raw frame verbatim, so a tracer reading
/// `user_regs_struct.r15` actually got the syscall number. Pin every field.
#[test]
fn x86_frame_maps_onto_the_right_user_regs_fields() {
    let f = frame();
    let u = x86::to_user_regs(&f, 0x1234, &seg());
    assert_eq!(u[x86::U_R15], f[x86::F_R15]);
    assert_eq!(u[x86::U_R14], f[x86::F_R14]);
    assert_eq!(u[x86::U_R13], f[x86::F_R13]);
    assert_eq!(u[x86::U_R12], f[x86::F_R12]);
    assert_eq!(u[x86::U_RBP], f[x86::F_RBP]);
    assert_eq!(u[x86::U_RBX], f[x86::F_RBX]);
    assert_eq!(u[x86::U_R10], f[x86::F_R10]);
    assert_eq!(u[x86::U_R9],  f[x86::F_R9]);
    assert_eq!(u[x86::U_R8],  f[x86::F_R8]);
    assert_eq!(u[x86::U_RDX], f[x86::F_RDX]);
    assert_eq!(u[x86::U_RSI], f[x86::F_RSI]);
    assert_eq!(u[x86::U_RDI], f[x86::F_RDI]);
    assert_eq!(u[x86::U_RSP], f[x86::F_RSP]);
    assert_eq!(u[x86::U_ORIG_RAX], f[x86::F_ORIG_RAX]);
    // SYSCALL parks user RIP in rcx and user RFLAGS in r11 — Linux reports
    // both the architectural register and the derived field.
    assert_eq!(u[x86::U_RIP], f[x86::F_RIP]);
    assert_eq!(u[x86::U_RCX], f[x86::F_RIP]);
    assert_eq!(u[x86::U_EFLAGS], f[x86::F_RFLAGS]);
    assert_eq!(u[x86::U_R11], f[x86::F_RFLAGS]);
    assert_eq!(u[x86::U_RAX], 0x1234);
    assert_eq!(u[x86::U_CS], 0x4b);
    assert_eq!(u[x86::U_SS], 0x43);
    assert_eq!(u[x86::U_FS_BASE], 0x7f00_0000_0000);
}

#[test]
fn x86_round_trip_preserves_every_general_register() {
    let f0 = frame();
    let mut s = seg();
    let u = x86::to_user_regs(&f0, 0x1234, &s);
    let mut f1 = [0u64; x86::FRAME_N];
    // Seed RFLAGS with kernel-only bits to prove they survive.
    f1[x86::F_RFLAGS] = 0x200; // IF
    let rax = x86::from_user_regs(&u, &mut f1, &mut s, 0x0000_8000_0000_0000).unwrap();
    assert_eq!(rax, 0x1234);
    for i in [x86::F_R15, x86::F_R14, x86::F_R13, x86::F_R12, x86::F_RBP, x86::F_RBX,
              x86::F_R10, x86::F_R9, x86::F_R8, x86::F_RDX, x86::F_RSI, x86::F_RDI,
              x86::F_ORIG_RAX, x86::F_RIP, x86::F_RSP] {
        assert_eq!(f1[i], f0[i], "frame slot {i}");
    }
}

#[test]
fn x86_setregs_cannot_clear_the_interrupt_flag() {
    let mut f = [0u64; x86::FRAME_N];
    f[x86::F_RFLAGS] = 0x202; // IF | reserved
    let mut s = seg();
    let mut u = [0u64; x86::N];
    u[x86::U_CS] = 0x4b; u[x86::U_SS] = 0x43;
    u[x86::U_EFLAGS] = 0x101; // CF | TF, IF clear
    x86::from_user_regs(&u, &mut f, &mut s, 0x0000_8000_0000_0000).unwrap();
    assert_eq!(f[x86::F_RFLAGS] & 0x200, 0x200, "IF must be preserved");
    assert_eq!(f[x86::F_RFLAGS] & 0x101, 0x101, "CF|TF must be installed");
}

#[test]
fn x86_setregs_rejects_a_ring0_selector() {
    let mut f = [0u64; x86::FRAME_N];
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
    let mut f = [0u64; x86::FRAME_N];
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

fn arm_frame() -> [u64; arm64::FRAME_N] {
    let mut f = [0u64; arm64::FRAME_N];
    for i in 0..arm64::FRAME_N { f[i] = 0xB000 + i as u64; }
    f[arm64::F_SPSR] = 0; // valid EL0t
    f
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
    for i in 1..18 { assert_eq!(u[i], f[arm64::F_X0 + i], "x{i}"); }
    assert_eq!(u[18], f[arm64::F_X18]);
    for i in 19..=28 { assert_eq!(u[i], f[arm64::F_X19 + (i - 19)], "x{i}"); }
    assert_eq!(u[29], f[arm64::F_X29]);
    assert_eq!(u[30], f[arm64::F_X30]);
    assert_eq!(u[arm64::U_SP], f[arm64::F_SP_EL0]);
    assert_eq!(u[arm64::U_PC], f[arm64::F_ELR]);
    assert_eq!(u[arm64::U_PSTATE], f[arm64::F_SPSR]);
}

#[test]
fn arm64_round_trip_preserves_every_register() {
    let f0 = arm_frame();
    let u = arm64::to_user_pt_regs(&f0, f0[arm64::F_X0]);
    let mut f1 = [0u64; arm64::FRAME_N];
    arm64::from_user_pt_regs(&u, &mut f1);
    for i in 0..=arm64::F_X30 {
        if i == 21 { continue; } // stp padding slot, not a register
        assert_eq!(f1[i], f0[i], "frame slot {i}");
    }
    for i in 0..10 { assert_eq!(f1[arm64::F_X19 + i], f0[arm64::F_X19 + i]); }
    assert_eq!(f1[arm64::F_SP_EL0], f0[arm64::F_SP_EL0]);
    assert_eq!(f1[arm64::F_ELR], f0[arm64::F_ELR]);
    assert_eq!(f1[arm64::F_RETVAL], f0[arm64::F_X0]);
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
