// Host tests for the aarch64 rt_sigframe: placement, UAPI shape, and an
// end-to-end round trip of a REAL frame in memory — the only kind of test
// that catches "the pure layout module is right but nothing calls it".

use super::*;

/// A user SP the process pointed at the TTBR1 half (`mov sp, <kernel VA>;
/// svc #0`) must not yield a writable placement: EL1 writes through TTBR1
/// happily, so the builder would land the frame in kernel memory.
#[test]
fn kernel_stack_pointer_yields_no_signal_frame() {
    let none = hal::AltStack::default();
    for sp in [hal::USER_VA_END + 0x10000, 0xffff_0000_0800_0000,
               0xffff_8000_0000_0000, 0xffff_ffff_ffff_f000, u64::MAX] {
        assert!(sigframe_range(sp, none).is_none(), "sp {sp:#x} accepted");
    }
    // The invariant, swept across the whole boundary: an accepted frame is
    // ALWAYS entirely inside user space — including the frame record, which
    // sits ABOVE the rt_sigframe.
    for d in 0..0x4000u64 {
        let sp = hal::USER_VA_END - 0x2000 + d;
        if let Some((base, len, _)) = sigframe_range(sp, none) {
            assert!(base + len <= hal::USER_VA_END, "sp {sp:#x} frame escapes user VA");
            let l = frame_layout(sp, none).unwrap();
            assert!(l.next_frame + FRAME_RECORD_BYTES <= hal::USER_VA_END,
                    "frame record escapes user VA");
        }
    }
}

#[test]
fn a_tiny_or_wrapping_stack_pointer_is_rejected_not_wrapped() {
    let none = hal::AltStack::default();
    for sp in [0u64, 1, 0x1000, core::mem::size_of::<RtSigframe>() as u64] {
        assert!(sigframe_range(sp, none).is_none(), "sp {sp:#x} accepted");
    }
    let alt = hal::AltStack { sp: u64::MAX - 0x100, size: 0x1000, flags: 0, use_alt: true };
    assert!(sigframe_range(0x7fff_0000_0000, alt).is_none());
    let alt = hal::AltStack { sp: hal::USER_VA_END - 0x1000, size: 0x9000, flags: 0, use_alt: true };
    assert!(sigframe_range(0x7fff_0000_0000, alt).is_none());
}

#[test]
fn handler_entry_sp_is_16_aligned_and_below_the_interrupted_sp() {
    let none = hal::AltStack::default();
    let sp = 0x7fff_ffff_e008u64;   // deliberately misaligned input
    let (base, len, align) = sigframe_range(sp, none).unwrap();
    assert_eq!(base % FRAME_ALIGN, 0, "54§3.4 AAPCS64 sp%16==0");
    assert_eq!(align, FRAME_ALIGN);
    // Linux's `access_ok(user->sigframe, sp_top - sp)` — the span reaches the
    // top, so it covers the frame record too.
    assert_eq!(len, sp - base);
    // AArch64 has no red zone: the region ends at the interrupted SP.
    assert!(base + len <= sp);
    let alt = hal::AltStack { sp: 0x1000_0000, size: 0x8000, flags: 0, use_alt: true };
    let (abase, alen, _) = sigframe_range(sp, alt).unwrap();
    assert!(abase >= alt.sp && abase + alen <= alt.sp + alt.size);
    assert_eq!(abase % FRAME_ALIGN, 0);
}

/// Linux `get_sigframe`: the `{ fp, lr }` record sits between the frame and
/// `sp_top`, 16-aligned, and never overlaps the rt_sigframe.
#[test]
fn the_frame_record_sits_above_the_rt_sigframe_and_below_sigsp() {
    let none = hal::AltStack::default();
    for d in 0..64u64 {
        let sp = 0x7fff_ffff_e000u64 + d;
        let l = frame_layout(sp, none).unwrap();
        assert_eq!(l.next_frame % FRAME_ALIGN, 0);
        assert_eq!(l.next_frame, l.sp + core::mem::size_of::<RtSigframe>() as u64);
        assert!(l.next_frame + FRAME_RECORD_BYTES <= l.top);
        assert_eq!(l.top, sp);
    }
}

#[test]
fn aarch64_rt_sigframe_matches_linux_uapi_shape() {
    assert_eq!(core::mem::offset_of!(Sigctx, regs), 8);
    assert_eq!(core::mem::offset_of!(Sigctx, sp), 256);
    assert_eq!(core::mem::offset_of!(Sigctx, pc), 264);
    assert_eq!(core::mem::offset_of!(Sigctx, pstate), 272);
    // `__u8 __reserved[4096] __attribute__((__aligned__(16)))` — 280 rounded
    // UP to 288. Getting this wrong shifted the whole record chain by 8 and
    // made `parse_user_sigframe`'s opening alignment check fail.
    assert_eq!(core::mem::offset_of!(Sigctx, __reserved), 288);
    assert_eq!(core::mem::size_of::<Sigctx>(), 4384);
    assert_eq!(core::mem::offset_of!(Ucontext, uc_mcontext), 176);
    assert_eq!(core::mem::offset_of!(RtSigframe, uc), 128);
    assert_eq!(core::mem::size_of::<RtSigframe>(), 4688);
    assert_eq!(RESERVED_IN_FRAME, 592);
    assert_eq!(RESERVED_IN_FRAME % records::RECORD_ALIGN, 0);
}

/// Linux `minsigstksz_setup()`. `MINSIGSTKSZ` on arm64 is 5120 and the real
/// frame must fit inside it, or every `sigaltstack(2)` sized to the legacy
/// constant overflows on the first delivery.
#[test]
fn at_minsigstksz_covers_the_frame_and_fits_the_legacy_minsigstksz() {
    let v = min_sigstksz();
    assert_eq!(v, core::mem::size_of::<RtSigframe>() + 16 + 16);
    let none = hal::AltStack::default();
    let sp = 0x7fff_ffff_e008u64;
    let (_, len, _) = sigframe_range(sp, none).unwrap();
    assert!(v as u64 >= len, "AT_MINSIGSTKSZ smaller than a real delivery");
    assert!(v <= 5120, "the frame must still fit arm64's MINSIGSTKSZ");
}

/// End-to-end `rt_sigreturn` over a REAL rt_sigframe in memory, driving the
/// same code the kernel runs. The host's stack lives below `USER_VA_END`, so
/// the "user" frame is just a 16-aligned local — no target gate, no boot.
/// This is the wiring test the pure-function tests cannot cover: before B1459
/// `restore_signal_frame` did `frame.spsr_el1 = mc.pstate` and every case
/// below "succeeded"; before B1466 the frame carried NO fpsimd record and
/// `rt_sigreturn` accepted it, which Linux's own parser does not.
#[repr(align(16))]
struct AlignedFrame(RtSigframe);

struct Out {
    ret: Option<(u64, i64, hal::AltStack, bool)>,
    spsr: u64,
    fpu: [u8; crate::FPU_STATE_BYTES],
}

/// Build a frame with the given pstate and (optionally) a real FPSIMD record
/// carrying `q_fill`, then run `restore_signal_frame` over it.
fn sigreturn_with(pstate: u64, with_fpsimd: bool, q_fill: u8) -> Out {
    // SAFETY: RtSigframe is plain-old-data (repr(C) integers + byte arrays); an all-zero bit pattern is a valid instance and every field the restore reads is set below.
    let mut uframe: AlignedFrame = unsafe { core::mem::zeroed() };
    uframe.0.uc.uc_mcontext.pstate = pstate;
    uframe.0.uc.uc_mcontext.pc = 0x1000;
    uframe.0.uc.uc_mcontext.sp = 0x2000;
    uframe.0.uc.uc_mcontext.regs[0] = 0x1234;
    if with_fpsimd {
        let q = [q_fill; 32 * 16];
        assert!(records::write_chain(&mut uframe.0.uc.uc_mcontext.__reserved, &q, 0x0080_0000, 0x10, None));
    }
    let base = &uframe.0 as *const RtSigframe as u64;
    assert!(base % FRAME_ALIGN == 0 && base + core::mem::size_of::<RtSigframe>() as u64 <= hal::USER_VA_END,
            "host stack must model a user address for this test");
    let mut svc: SvcFrame = SvcFrame {
        gp: [0; 18], x18_x29: [0; 2], x30: 0, _pad_x30: 0,
        elr_el1: 0xdead, spsr_el1: 0xbeef, sp_el0: base, retval: 0, x19_x28: [0; 10],
    };
    let mut fpu = [0xeeu8; crate::FPU_STATE_BYTES];
    // SAFETY: `svc` is a live exclusively-owned frame and `base` a live
    // rt_sigframe, exactly the contract `restore_signal_frame` states.
    let ret = unsafe { restore_signal_frame(&mut svc, &mut fpu) };
    Out { ret, spsr: svc.spsr_el1, fpu }
}

#[test]
fn rt_sigreturn_rejects_a_forged_el1_pstate_end_to_end() {
    // M[3:0] = 0b0101 = EL1h. The SVC exit does `msr spsr_el1, x10` from
    // this slot and `eret`s — accepting it runs user code at EL1.
    let o = sigreturn_with(0x3c5, true, 0);
    assert!(o.ret.is_none(), "forged EL1h pstate accepted by rt_sigreturn");
    assert_eq!(o.spsr, 0xbeef, "the SVC frame must be left untouched on a bad frame");
}

#[test]
fn rt_sigreturn_accepts_a_normal_el0_pstate_end_to_end() {
    let o = sigreturn_with(hal::uregs::aarch64::PSR_NZCV, true, 0);
    let (_, x0, _, _) = o.ret.expect("a legal EL0t pstate must round-trip");
    assert_eq!(x0, 0x1234);
    assert_eq!(o.spsr, hal::uregs::aarch64::PSR_NZCV);
}

#[test]
fn rt_sigreturn_masks_res0_bits_end_to_end() {
    use hal::uregs::aarch64::{PSR_IL_BIT, PSR_NZCV, PSR_SS_BIT};
    let o = sigreturn_with(PSR_NZCV | PSR_IL_BIT | PSR_SS_BIT, true, 0);
    assert!(o.ret.is_some());
    assert_eq!(o.spsr, PSR_NZCV, "IL / SS reached SPSR_EL1");
}

/// THE assertion this branch exists for. Linux `restore_sigframe`:
/// `if (!user.fpsimd) return -EINVAL`. The frame we shipped before B1466 was
/// an all-zero `__reserved` — an immediate terminator, no FPSIMD record — so
/// this case is exactly the frame that used to be built, and Linux's own
/// kernel rejects it.
#[test]
fn rt_sigreturn_rejects_a_frame_with_no_fpsimd_record() {
    let o = sigreturn_with(hal::uregs::aarch64::PSR_NZCV, false, 0);
    assert!(o.ret.is_none(), "a frame with no FPSIMD record must be -EINVAL (signal.c:1044)");
    assert_eq!(o.spsr, 0xbeef, "the SVC frame must be left untouched");
}

/// The registers must actually come back. A restore that parsed the record
/// and then dropped it on the floor would pass every structural test above.
#[test]
fn rt_sigreturn_loads_the_q_registers_and_control_words_from_the_record() {
    let o = sigreturn_with(hal::uregs::aarch64::PSR_NZCV, true, 0xa7);
    let (_, _, _, dirty) = o.ret.expect("frame must restore");
    assert!(dirty, "the caller is told to reload the FP/SIMD registers");
    assert!(o.fpu[..crate::FPU_VREGS_BYTES].iter().all(|b| *b == 0xa7),
            "Q registers not restored from the frame's fpsimd_context");
    let mut c = [0u8; 4]; c.copy_from_slice(&o.fpu[crate::FPU_FPCR_OFF..crate::FPU_FPCR_OFF + 4]);
    let mut s = [0u8; 4]; s.copy_from_slice(&o.fpu[crate::FPU_FPSR_OFF..crate::FPU_FPSR_OFF + 4]);
    // fpsr precedes fpcr in the record and follows it in the save area;
    // swapping them would put FPCR's value in FPSR and silently change
    // rounding mode / exception masking for the resumed thread.
    assert_eq!(u32::from_le_bytes(c), 0x0080_0000, "FPCR mis-decoded");
    assert_eq!(u32::from_le_bytes(s), 0x10, "FPSR mis-decoded");
}

/// The full delivery→return round trip: a `build_signal_frame` image must be
/// one `restore_signal_frame` accepts, with the Q registers byte-identical.
#[test]
fn a_built_frame_round_trips_its_fpsimd_state_back_out() {
    let mut saved = [0u8; crate::FPU_STATE_BYTES];
    for (i, b) in saved[..crate::FPU_VREGS_BYTES].iter_mut().enumerate() { *b = (i as u8) ^ 0x99; }
    saved[crate::FPU_FPCR_OFF..crate::FPU_FPCR_OFF + 4].copy_from_slice(&0x0060_0000u32.to_le_bytes());
    saved[crate::FPU_FPSR_OFF..crate::FPU_FPSR_OFF + 4].copy_from_slice(&0x1000_0000u32.to_le_bytes());

    // A 16-aligned "user stack" on the host stack, big enough for the frame
    // plus its frame record.
    #[repr(align(16))]
    struct Stack([u8; core::mem::size_of::<RtSigframe>() + 64]);
    let mut stack = Stack([0u8; core::mem::size_of::<RtSigframe>() + 64]);
    let top = (&mut stack.0 as *mut _ as u64) + stack.0.len() as u64;
    let top = top & !15;
    let mut svc: SvcFrame = SvcFrame {
        gp: [0; 18], x18_x29: [0xaa; 2], x30: 0xbb, _pad_x30: 0,
        elr_el1: 0x4000, spsr_el1: hal::uregs::aarch64::PSR_NZCV, sp_el0: top,
        retval: 0, x19_x28: [0; 10],
    };
    // SAFETY: `svc` is exclusively owned here and `top` addresses the host-stack buffer above, which models the user stack the builder writes.
    assert!(unsafe { build_signal_frame(&mut svc, 0x5000, 0x6000, 11, 0, false, 0,
                                        None, hal::AltStack::default(), &saved) });
    // Linux `setup_return`: x29 points at the synthetic record, whose fp/lr
    // are the INTERRUPTED frame's — that is what lets an unwinder step out.
    let l = frame_layout(top, hal::AltStack::default()).unwrap();
    assert_eq!(svc.x18_x29[X29], l.next_frame);
    // SAFETY: `l.next_frame` is inside the host-stack buffer the builder just wrote, 16-aligned, and holds the `{fp, lr}` pair.
    let rec = unsafe { core::ptr::read_volatile(l.next_frame as *const [u64; 2]) };
    assert_eq!(rec, [0xaa, 0xbb], "frame record must carry the interrupted x29/x30");

    // Now sigreturn off the frame the builder produced.
    let mut back = [0u8; crate::FPU_STATE_BYTES];
    // SAFETY: `svc.sp_el0` is the frame the builder just wrote into the host-stack buffer, matching `restore_signal_frame`'s contract.
    let out = unsafe { restore_signal_frame(&mut svc, &mut back) };
    let (_, _, _, dirty) = out.expect("a frame we built must be one we accept");
    assert!(dirty);
    assert_eq!(&back[..crate::FPU_VREGS_BYTES], &saved[..crate::FPU_VREGS_BYTES],
               "Q registers changed across delivery + return");
    assert_eq!(&back[crate::FPU_FPCR_OFF..crate::FPU_FPCR_OFF + 4],
               &saved[crate::FPU_FPCR_OFF..crate::FPU_FPCR_OFF + 4], "FPCR changed");
    assert_eq!(&back[crate::FPU_FPSR_OFF..crate::FPU_FPSR_OFF + 4],
               &saved[crate::FPU_FPSR_OFF..crate::FPU_FPSR_OFF + 4], "FPSR changed");
}
