// Host tests for the x86_64 rt_sigframe: placement, UAPI shape, and the
// FPU/xstate area's presence in a REAL frame built in memory.

use super::*;

/// Both frame shapes this HAL can emit: the XSAVE area size a modern CPU
/// reports, and the FXSAVE fallback (`xsave_area_bytes() == 0`).
const XSAVE_AREA_AVX512: usize = 2696;

fn math_avx512() -> u64 { xstate::math_frame_size(XSAVE_AREA_AVX512) as u64 }
fn math_fxsave() -> u64 { xstate::math_frame_size(0) as u64 }

/// A user SP the process pointed at the kernel half of the address space
/// (`mov rsp, <kernel VA>; syscall`) must not yield a writable placement:
/// the builder's `write_volatile` runs at CPL0 through the live CR3 and
/// would land an attacker-shaped frame in kernel memory.
#[test]
fn kernel_stack_pointer_yields_no_signal_frame() {
    let none = hal::AltStack::default();
    for math in [math_avx512(), math_fxsave()] {
        for sp in [hal::USER_VA_END + 0x10000, 0xffff_ffff_8100_0000,
                   0xffff_8000_0000_0000, 0xffff_ffff_ffff_f000, u64::MAX] {
            assert!(frame_span(sp, none, math).is_none(), "sp {sp:#x} accepted");
        }
    }
}

#[test]
fn a_frame_ending_past_the_user_boundary_is_rejected() {
    let none = hal::AltStack::default();
    // The invariant, swept across the whole boundary: an accepted frame is
    // ALWAYS entirely inside user space — INCLUDING the xstate area, which
    // sits ABOVE the rt_sigframe and is the part a `sizeof(RtSigframe)`-only
    // bound would miss.
    for math in [math_avx512(), math_fxsave()] {
        for d in 0..0x4000u64 {
            let sp = hal::USER_VA_END - 0x2000 + d;
            if let Some((base, len, _)) = frame_span(sp, none, math) {
                assert!(base + len <= hal::USER_VA_END, "sp {sp:#x} frame escapes user VA");
                let l = frame_layout(sp, none, math).unwrap();
                assert!(l.fpstate + l.math <= hal::USER_VA_END, "xstate area escapes user VA");
            }
        }
    }
    // An alt stack whose top is in kernel space is rejected the same way.
    let alt = hal::AltStack { sp: hal::USER_VA_END - 0x1000, size: 0x4000, flags: 0, use_alt: true };
    assert!(frame_span(0x7fff_0000_0000, alt, math_avx512()).is_none());
}

#[test]
fn a_tiny_or_wrapping_stack_pointer_is_rejected_not_wrapped() {
    let none = hal::AltStack::default();
    let fsz = core::mem::size_of::<RtSigframe>() as u64;
    for math in [math_avx512(), math_fxsave()] {
        for sp in [0u64, 1, RED_ZONE, RED_ZONE + 8, RED_ZONE + fsz,
                   RED_ZONE + fsz + math, RED_ZONE + fsz + math + PRETCODE_BYTES - 1] {
            assert!(frame_span(sp, none, math).is_none(), "sp {sp:#x} math {math} accepted");
            assert!(frame_layout(sp, none, math).is_none(), "sp {sp:#x} base wrapped");
        }
    }
    // Overflowing alt-stack top must not wrap into a low user address.
    let alt = hal::AltStack { sp: u64::MAX - 0x100, size: 0x1000, flags: 0, use_alt: true };
    assert!(frame_span(0x7fff_0000_0000, alt, math_avx512()).is_none());
}

#[test]
fn handler_entry_sp_is_16n_plus_8_below_the_red_zone() {
    let none = hal::AltStack::default();
    let sp = 0x7fff_ffff_e000u64;
    let math = math_avx512();
    let (base, len, align) = frame_span(sp, none, math).unwrap();
    assert_eq!(base % FRAME_ALIGN, PRETCODE_BYTES, "54§3.3 handler-entry alignment");
    assert_eq!(align, PRETCODE_BYTES);
    assert!(base + len <= sp - RED_ZONE, "frame overlaps the red zone");
    // The span now covers the rt_sigframe AND the xstate area above it.
    assert_eq!(len, core::mem::size_of::<RtSigframe>() as u64 + math + pad(sp, math));
    // The alt-stack arm places the frame at the alt stack's TOP, with no
    // red zone: nothing owns memory below a fresh alt stack.
    let alt = hal::AltStack { sp: 0x1000_0000, size: 0x8000, flags: 0, use_alt: true };
    let (abase, alen, _) = frame_span(sp, alt, math).unwrap();
    assert!(abase >= alt.sp && abase + alen <= alt.sp + alt.size);
    assert_eq!(abase % FRAME_ALIGN, PRETCODE_BYTES);
}

/// Alignment slack between the rt_sigframe's end and the xstate base, for the
/// span-length assertion above.
fn pad(sp: u64, math: u64) -> u64 {
    let l = frame_layout(sp, hal::AltStack::default(), math).unwrap();
    l.fpstate - (l.sp + core::mem::size_of::<RtSigframe>() as u64)
}

/// Linux `fpu__alloc_mathframe`: `round_down(sp - frame_size, 64)`. XSAVE
/// #GPs below 64-byte alignment, so this is not cosmetic.
#[test]
fn the_xstate_area_is_64_byte_aligned_and_above_the_rt_sigframe() {
    let none = hal::AltStack::default();
    for d in 0..512u64 {
        let sp = 0x7fff_ffff_e000u64 + d;
        for math in [math_avx512(), math_fxsave()] {
            let l = frame_layout(sp, none, math).unwrap();
            assert_eq!(l.fpstate % xstate::XSTATE_ALIGN, 0, "sp {sp:#x} fpstate misaligned");
            // `54§3.1`: everything the kernel wrote must sit AT or ABOVE the
            // handler's entry SP, or the handler's own frames trample it.
            assert!(l.fpstate >= l.sp + core::mem::size_of::<RtSigframe>() as u64,
                    "xstate area overlaps the rt_sigframe");
            assert!(l.fpstate + l.math <= sp - RED_ZONE, "xstate area overlaps the red zone");
        }
    }
}

#[test]
fn x86_64_rt_sigframe_matches_linux_uapi_shape() {
    assert_eq!(core::mem::offset_of!(Sigctx, rip), 128);
    assert_eq!(core::mem::offset_of!(Sigctx, eflags), 136);
    assert_eq!(core::mem::offset_of!(Sigctx, cr2), 176);
    // `sigcontext_64.fpstate` — the pointer that was hardcoded to 0 until
    // B1466 and is what every JVM/Go/sanitizer handler reads for FP context.
    assert_eq!(core::mem::offset_of!(Sigctx, fpstate), 184);
    assert_eq!(core::mem::size_of::<Sigctx>(), 256);
    assert_eq!(core::mem::offset_of!(Ucontext, uc_mcontext), 40);
    assert_eq!(core::mem::offset_of!(Ucontext, uc_sigmask), 296);
    assert_eq!(core::mem::offset_of!(RtSigframe, uc), 8);
}

/// Linux `get_sigframe_size()`, the `AT_MINSIGSTKSZ` value. It MUST exceed
/// the legacy `MINSIGSTKSZ` (2048) on any XSAVE CPU — that gap is exactly
/// why Linux exports it in the auxv.
#[test]
fn at_minsigstksz_covers_the_whole_frame_including_the_xstate_area() {
    let uctxt = core::mem::size_of::<RtSigframe>();
    for area in [0usize, 576, 1088, XSAVE_AREA_AVX512, 4096] {
        let v = xstate::min_sigstksz(uctxt, area);
        assert_eq!(v % 16, 0, "userspace expects an aligned size");
        let math = xstate::math_frame_size(area) as u64;
        // Big enough for the worst-case placement out of any SP: frame +
        // xstate + both alignment paddings.
        let sp = 0x7fff_ffff_e000u64 + 8;
        let top = sp;
        let l = frame_layout(sp, hal::AltStack::default(), math).unwrap();
        assert!((v as u64) >= (top - RED_ZONE) - l.sp, "AT_MINSIGSTKSZ {v} too small for area {area}");
    }
    assert!(xstate::min_sigstksz(uctxt, XSAVE_AREA_AVX512) > 2048,
            "an AVX512 frame does not fit in the legacy MINSIGSTKSZ; that is the point of AT_MINSIGSTKSZ");
}

/// Linux `get_sigframe`'s alt-stack overflow guard: "If we are on the
/// alternate signal stack and would overflow it, don't. Return an
/// always-bogus address instead so we will die with SIGSEGV."
///
/// Load-bearing since the frame started carrying the XSAVE area: an
/// `sigaltstack(2)` sized to the legacy `MINSIGSTKSZ` (2048) no longer fits
/// one, and Linux's own `sigaltstack(2)` still accepts that size — which is
/// why `AT_MINSIGSTKSZ` exists. Without the guard the frame lands BELOW the
/// alternate stack, over whatever is there.
#[test]
fn an_alt_stack_too_small_for_the_frame_is_refused_not_overrun() {
    let base = 0x2000_0000u64;
    let sp = 0x7fff_ffff_e000u64;
    for math in [math_avx512(), math_fxsave()] {
        let need = core::mem::size_of::<RtSigframe>() as u64 + math;
        // Anything comfortably larger than the frame is accepted and lands
        // wholly inside the alternate stack.
        let alt = hal::AltStack { sp: base, size: need + 4096, flags: 0, use_alt: true };
        let (b, len, _) = frame_span(sp, alt, math).expect("a big enough alt stack must work");
        assert!(b > alt.sp && b + len <= alt.sp + alt.size);
        // The legacy MINSIGSTKSZ and every size below the real requirement
        // must be refused rather than carved out from under the stack.
        for size in [2048u64, need - 16, need / 2, 16] {
            let alt = hal::AltStack { sp: base, size, flags: 0, use_alt: true };
            if let Some((b, _, _)) = frame_span(sp, alt, math) {
                assert!(b > alt.sp, "frame at {b:#x} carved below a {size}-byte alt stack");
            }
        }
        // Specifically: an AVX512 frame does not fit 2048 bytes, so that case
        // must be refused outright.
        if math == math_avx512() {
            let alt = hal::AltStack { sp: base, size: 2048, flags: 0, use_alt: true };
            assert!(frame_span(sp, alt, math).is_none(),
                    "a 2048-byte alt stack accepted for a frame that cannot fit");
        }
    }
}
