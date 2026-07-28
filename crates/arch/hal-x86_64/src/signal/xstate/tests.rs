// Host tests for the `uc_mcontext.fpstate` area: the exact layout Linux
// stamps, and the exact accept / degrade / reject partition its restore path
// applies to a user-supplied image.

use super::*;

/// A plausible XSAVE area for x87+SSE+AVX+AVX512 on a modern CPU.
const AREA: usize = 2696;
/// XCR0 the kernel programs for that area (x87|SSE|AVX|opmask|Hi256|Hi16).
const XCR0: u64 = 0b1110_0111;
const MXCSR_MASK: u32 = 0xffff;

fn wr32(b: &mut [u8], off: usize, v: u32) { b[off..off + 4].copy_from_slice(&v.to_le_bytes()); }
fn wr64(b: &mut [u8], off: usize, v: u64) { b[off..off + 8].copy_from_slice(&v.to_le_bytes()); }
fn rd64(b: &[u8], off: usize) -> u64 { read_u64(b, off) }

/// A well-formed frame image exactly as `write_epilog` would leave it.
/// Byte count of a full AVX512-shaped math frame; the tests are no_std, so
/// every buffer is a fixed array of exactly this size.
const N: usize = AREA + 4;

fn good_image() -> [u8; N] {
    let mut img = [0u8; N];
    wr32(&mut img, MXCSR_OFF, 0x1f80);
    wr64(&mut img, XFEATURES_OFF, 0b111); // x87|SSE|AVX live
    assert!(write_epilog(&mut img, AREA, XCR0));
    img
}

#[test]
fn sizes_match_the_linux_uapi_structs() {
    assert_eq!(FXSAVE_BYTES, 512);
    assert_eq!(XSTATE_HEADER_BYTES, 64);
    assert_eq!(MIN_XSTATE_SIZE, 576);
    assert_eq!(SW_RESERVED_OFF, 464);
    assert_eq!(core::mem::size_of::<FpxSwBytes>(), 48);
    assert_eq!(FP_XSTATE_MAGIC2_SIZE, 4);
    // `xstate_sigframe_size()`: user_size + the MAGIC2 trailer under XSAVE,
    // the bare 512-byte legacy image on the FXSAVE fallback.
    assert_eq!(math_frame_size(AREA), AREA + 4);
    assert_eq!(math_frame_size(0), 512);
    assert_eq!(user_xstate_size(0), 512);
}

/// Linux `save_xstate_epilog()`: the SW footer at 464, the MAGIC2 trailer at
/// `user_size`, and FP|SSE forced into XSTATE_BV.
#[test]
fn write_epilog_stamps_the_footer_trailer_and_fpsse_bits() {
    let img = good_image();
    let sw = read_sw_bytes(&img).unwrap();
    assert_eq!(sw.magic1, FP_XSTATE_MAGIC1);
    assert_eq!(sw.xstate_size as usize, AREA);
    assert_eq!(sw.extended_size as usize, AREA + 4);
    assert_eq!(sw.xfeatures, XCR0);
    assert_eq!(read_trailer(&img, AREA), FP_XSTATE_MAGIC2);
    assert_eq!(rd64(&img, XFEATURES_OFF) & XFEATURE_MASK_FPSSE, XFEATURE_MASK_FPSSE);
}

/// The FXSAVE fallback writes the footer but NO trailer — there is no
/// extended area for one to terminate.
#[test]
fn the_fxsave_fallback_writes_no_magic2_trailer() {
    let mut img = [0u8; 512];
    assert!(write_epilog(&mut img, 0, 0));
    assert_eq!(read_sw_bytes(&img).unwrap().magic1, FP_XSTATE_MAGIC1);
    assert_eq!(math_frame_size(0), 512, "no room for a trailer past the legacy image");
}

/// Linux `check_xstate_in_sigframe()` degrades — it does NOT reject. Each
/// malformed header below lands on `setfx:`, which restores the legacy 512
/// bytes and re-initialises every other component.
#[test]
fn a_forged_or_truncated_xstate_header_degrades_to_fx_only_not_an_error() {
    let base = FpxSwBytes { magic1: FP_XSTATE_MAGIC1, extended_size: (AREA + 4) as u32,
                            xfeatures: XCR0, xstate_size: AREA as u32, padding: [0; 7] };
    assert_eq!(check_xstate_in_sigframe(&base, FP_XSTATE_MAGIC2, AREA),
               SwCheck::Xstate { xstate_size: AREA, xfeatures: XCR0 });

    let mut bad = base; bad.magic1 = 0xdead_beef;
    assert_eq!(check_xstate_in_sigframe(&bad, FP_XSTATE_MAGIC2, AREA), SwCheck::FxOnly,
               "forged magic1");
    let mut bad = base; bad.xstate_size = (MIN_XSTATE_SIZE - 1) as u32;
    assert_eq!(check_xstate_in_sigframe(&bad, FP_XSTATE_MAGIC2, AREA), SwCheck::FxOnly,
               "xstate_size below the legacy+header floor");
    let mut bad = base; bad.xstate_size = (AREA + 1) as u32;
    assert_eq!(check_xstate_in_sigframe(&bad, FP_XSTATE_MAGIC2, AREA), SwCheck::FxOnly,
               "xstate_size larger than the kernel's own image");
    let mut bad = base; bad.extended_size = base.xstate_size - 1;
    assert_eq!(check_xstate_in_sigframe(&bad, FP_XSTATE_MAGIC2, AREA), SwCheck::FxOnly,
               "xstate_size > extended_size");
    assert_eq!(check_xstate_in_sigframe(&base, 0, AREA), SwCheck::FxOnly,
               "missing MAGIC2 trailer (a legacy-only copy)");
    // u32::MAX must not wrap anything into acceptance.
    let mut bad = base; bad.xstate_size = u32::MAX; bad.extended_size = u32::MAX;
    assert_eq!(check_xstate_in_sigframe(&bad, FP_XSTATE_MAGIC2, AREA), SwCheck::FxOnly);
}

/// Linux `validate_user_xstate_header()`. On x86_64's fast path these are the
/// conditions `XRSTOR` itself #GPs on; we copy-then-restore, so rejecting
/// here is what keeps a forged header from faulting inside the kernel.
#[test]
fn a_forged_xstate_header_is_rejected_the_way_xrstor_would_gp() {
    let img = good_image();
    assert!(header_is_valid(&img, XCR0));

    // A feature bit the kernel never enabled in XCR0.
    let mut bad = img.clone();
    wr64(&mut bad, XFEATURES_OFF, XCR0 | (1 << 17));
    assert!(!header_is_valid(&bad, XCR0), "unknown/supervisor feature bit accepted");

    // Compacted format — illegal in a user image.
    let mut bad = img.clone();
    wr64(&mut bad, XCOMP_BV_OFF, 1 << 63);
    assert!(!header_is_valid(&bad, XCR0), "xcomp_bv accepted");

    // Any of the 48 reserved header bytes.
    for i in 0..HDR_RESERVED_BYTES {
        let mut bad = img.clone();
        bad[HDR_RESERVED_OFF + i] = 1;
        assert!(!header_is_valid(&bad, XCR0), "reserved header byte {i} accepted");
    }

    // Truncated below the legacy+header floor.
    assert!(!header_is_valid(&img[..MIN_XSTATE_SIZE - 1], XCR0));
}

/// Linux's x86_64 arm rejects a reserved MXCSR bit outright ("Reject invalid
/// MXCSR values"); the 32-bit arm masks. We are 64-bit.
#[test]
fn a_reserved_mxcsr_bit_is_rejected() {
    let mut img = good_image();
    assert!(mxcsr_is_valid(&img, MXCSR_MASK));
    wr32(&mut img, MXCSR_OFF, 0x1f80 | 0x8000_0000);
    assert!(!mxcsr_is_valid(&img, MXCSR_MASK));
    let mut out = [0u8; N];
    assert!(!build_restore_image(&img, &mut out, SwCheck::Xstate { xstate_size: AREA, xfeatures: XCR0 },
                                 XCR0, MXCSR_MASK, true),
            "a reserved MXCSR bit must fail the sigreturn, not reach xrstor64");
}

/// The round trip that matters: what the kernel wrote must come back
/// byte-identical through the restore transform, or the interrupted context's
/// SIMD registers are silently changed.
#[test]
fn a_kernel_written_image_round_trips_through_restore_unchanged() {
    let mut img = good_image();
    // Seed distinctive XMM/YMM bytes so a dropped component is visible.
    for i in 0..256 { img[160 + i] = (i as u8) ^ 0x5a; }          // xmm_space
    for i in 0..256 { img[576 + i] = (i as u8) ^ 0xa5; }          // ymmh
    let sw = read_sw_bytes(&img).unwrap();
    let check = check_xstate_in_sigframe(&sw, read_trailer(&img, sw.xstate_size as usize), AREA);
    assert_eq!(check, SwCheck::Xstate { xstate_size: AREA, xfeatures: XCR0 });

    let mut out = [0u8; N];
    assert!(build_restore_image(&img, &mut out, check, XCR0, MXCSR_MASK, true));
    assert_eq!(&out[160..416], &img[160..416], "XMM state lost across sigreturn");
    assert_eq!(&out[576..832], &img[576..832], "YMM state lost across sigreturn");
    assert_eq!(rd64(&out, XFEATURES_OFF), 0b111 | XFEATURE_MASK_FPSSE);
    assert_eq!(read_u32(&out, MXCSR_OFF), 0x1f80);
}

/// The degraded arm: only the legacy 512 bytes survive, every extended
/// component goes back to init (XSTATE_BV bit clear ⇒ `xrstor64` inits it),
/// which is Linux's `fxrstor` + `os_xrstor(&init_fpstate, init_bv)` pair.
#[test]
fn fx_only_keeps_the_legacy_image_and_inits_every_extended_component() {
    let mut img = good_image();
    for i in 0..256 { img[160 + i] = 0x11; }
    for i in 0..256 { img[576 + i] = 0x22; }
    let mut out = [0u8; N];
    assert!(build_restore_image(&img, &mut out, SwCheck::FxOnly, XCR0, MXCSR_MASK, true));
    assert_eq!(&out[160..416], &img[160..416], "legacy XMM state must survive fx-only");
    assert_eq!(rd64(&out, XFEATURES_OFF), XFEATURE_MASK_FPSSE);
    assert!(out[576..].iter().all(|b| *b == 0), "extended area must be init, not user bytes");
}

/// Linux `xrestore &= fpu->fpstate->user_xfeatures`: a feature the kernel
/// does not offer is dropped from the restore, never handed to `xrstor64`.
#[test]
fn user_claimed_features_are_clamped_to_the_kernels_xcr0() {
    let mut img = good_image();
    wr64(&mut img, XFEATURES_OFF, 0b111);
    let mut out = [0u8; N];
    // The user claims AVX512 opmask (bit 5) in the SW footer while the header
    // says only x87|SSE|AVX; the intersection is what reaches the image.
    assert!(build_restore_image(&img, &mut out,
                                SwCheck::Xstate { xstate_size: AREA, xfeatures: !0 },
                                XCR0, MXCSR_MASK, true));
    assert_eq!(rd64(&out, XFEATURES_OFF), 0b111 & XCR0);
    // And a header claiming a bit outside XCR0 is rejected before that.
    wr64(&mut img, XFEATURES_OFF, 1 << 40);
    assert!(!build_restore_image(&img, &mut out,
                                 SwCheck::Xstate { xstate_size: AREA, xfeatures: !0 },
                                 XCR0, MXCSR_MASK, true));
}

/// Linux `fpu__clear_user_states`: `fpstate == 0` at sigreturn is legal and
/// means "init state". A zeroed FXSAVE image would leave MXCSR = 0 — every
/// SSE exception UNMASKED — so the fallback has to seed the control words.
#[test]
fn the_init_image_leaves_masked_control_words_on_the_fxsave_fallback() {
    let mut img = [0u8; 512];
    write_init_image(&mut img, false);
    assert_eq!(read_u32(&img, MXCSR_OFF), MXCSR_INIT, "unmasked MXCSR ⇒ spurious SIGFPE");
    assert_eq!(u16::from_le_bytes([img[0], img[1]]), FCW_INIT);
    // Under XSAVE the all-zero XSTATE_BV already means "init every
    // component", so the image is genuinely all zeros.
    let mut img = [0xffu8; N];
    write_init_image(&mut img, true);
    assert!(img.iter().all(|b| *b == 0));
}

/// A short buffer must never panic or half-write.
#[test]
fn undersized_buffers_are_refused() {
    let mut small = [0u8; 64];
    assert!(!write_epilog(&mut small, AREA, XCR0));
    assert!(read_sw_bytes(&small).is_none());
    assert_eq!(read_trailer(&small, 4096), 0);
    let img = good_image();
    let mut out = [0u8; 64];
    assert!(!build_restore_image(&img, &mut out, SwCheck::FxOnly, XCR0, MXCSR_MASK, true));
    assert!(!build_restore_image(&small, &mut [0u8; N], SwCheck::FxOnly,
                                 XCR0, MXCSR_MASK, true));
}
