// Hosted proof of the `acct_v3` wire format, the two numeric encodings, and
// the `acct_on` admission order. None of this needs a boot, and all of it is
// the part a userspace `sa`/`lastcomm` would silently mis-read if it drifted.

use super::*;
use super::record::*;

/// `sizeof(struct acct_v3) == 64` and the encoder fills exactly that.
#[test]
fn record_is_exactly_sixty_four_bytes() {
    assert_eq!(ACCT_V3_LEN, 64);
    assert_eq!(AcctFacts::default().encode().len(), 64);
}

/// Every field lands at the offset `include/uapi/linux/acct.h struct acct_v3`
/// puts it. Written as distinct sentinel values so a swapped pair of adjacent
/// fields cannot pass.
#[test]
fn field_offsets_match_struct_acct_v3() {
    let mut f = AcctFacts {
        flag: AFORK | AXSIG,
        tty: 0x0402,
        exitcode: 0x1122_3344,
        uid: 1000, gid: 1001,
        pid: 4242, ppid: 4241,
        btime: 0x6600_0000,
        ..Default::default()
    };
    f.set_comm(b"bash");
    let r = f.encode();
    assert_eq!(r[0], AFORK | AXSIG,                     "ac_flag @0");
    assert_eq!(r[1], ACCT_VERSION,                      "ac_version @1");
    assert_eq!(u16::from_le_bytes([r[2], r[3]]), 0x0402, "ac_tty @2");
    assert_eq!(u32::from_le_bytes([r[4], r[5], r[6], r[7]]), 0x1122_3344, "ac_exitcode @4");
    assert_eq!(u32::from_le_bytes([r[8], r[9], r[10], r[11]]), 1000, "ac_uid @8");
    assert_eq!(u32::from_le_bytes([r[12], r[13], r[14], r[15]]), 1001, "ac_gid @12");
    assert_eq!(u32::from_le_bytes([r[16], r[17], r[18], r[19]]), 4242, "ac_pid @16");
    assert_eq!(u32::from_le_bytes([r[20], r[21], r[22], r[23]]), 4241, "ac_ppid @20");
    assert_eq!(u32::from_le_bytes([r[24], r[25], r[26], r[27]]), 0x6600_0000, "ac_btime @24");
    assert_eq!(&r[48..52], b"bash", "ac_comm @48");
    assert_eq!(&r[52..64], &[0u8; 12], "ac_comm is NUL-padded to 16");
}

/// `ac_comm` is `ACCT_COMM` (16) wide in v3 with NO reserved terminator, so a
/// 16-byte name fills the field and must not be truncated to 15.
#[test]
fn comm_fills_all_sixteen_bytes_without_a_terminator() {
    let mut f = AcctFacts::default();
    f.set_comm(b"0123456789abcdefOVERFLOW");
    assert_eq!(&f.encode()[48..64], b"0123456789abcdef");
}

/// `nsec_to_AHZ` with AHZ=100 is exactly nanoseconds → centiseconds.
#[test]
fn nsec_to_ahz_is_centiseconds() {
    assert_eq!(nsec_to_ahz(0), 0);
    assert_eq!(nsec_to_ahz(10_000_000), 1);
    assert_eq!(nsec_to_ahz(1_000_000_000), 100);
    assert_eq!(nsec_to_ahz(9_999_999), 0, "sub-centisecond truncates, as Linux's do_div does");
}

/// `encode_comp_t` values computed from Linux's algorithm: below MAXFRACT the
/// value is stored verbatim, above it the base-8 exponent takes over, and the
/// whole thing saturates rather than wrapping.
#[test]
fn comp_t_matches_linux_encoding() {
    // <= MAXFRACT (8191): exponent 0, mantissa verbatim.
    assert_eq!(encode_comp_t(0), 0);
    assert_eq!(encode_comp_t(1), 1);
    assert_eq!(encode_comp_t(8191), 8191);
    // 8192 = 0x2000: one shift by 3 -> 1024, exp 1 -> (1 << 13) + 1024.
    assert_eq!(encode_comp_t(8192), (1 << 13) + 1024);
    // Saturation: exponent can hold 3 bits (max 7); beyond that, all ones.
    assert_eq!(encode_comp_t(u64::MAX), u16::MAX);
    // Monotonic non-decreasing across the whole low range — a rounding bug in
    // the carry path shows up here as a dip.
    let mut prev = 0u16;
    for v in 0..40_000u64 {
        let e = encode_comp_t(v);
        assert!(e >= prev, "encode_comp_t({v}) = {e} < previous {prev}");
        prev = e;
    }
}

/// `encode_float` produces the IEEE-754 single-precision bit pattern, which is
/// what `sa` reinterprets `ac_etime` as. Compared against `f32::to_bits` for
/// exactly-representable values.
#[test]
fn encode_float_matches_ieee754_single() {
    assert_eq!(encode_float(0), 0);
    for v in [1u64, 2, 3, 4, 100, 1024, 65536, 1_000_000, 1 << 40] {
        assert_eq!(encode_float(v), (v as f32).to_bits(), "encode_float({v})");
    }
}

/// `old_encode_dev` packs the 8-bit major/minor pair Linux stores in `ac_tty`.
#[test]
fn tty_device_number_is_old_encoded() {
    assert_eq!(old_encode_dev(0), 0, "no controlling terminal");
    // /dev/tty1 is 4:1.
    assert_eq!(old_encode_dev((4 << 8) | 1), 0x0401);
    // /dev/pts/3 is 136:3.
    assert_eq!(old_encode_dev((136 << 8) | 3), 0x8803);
}

/// `btime` is the wall clock minus the elapsed lifetime, in whole seconds.
#[test]
fn btime_is_now_minus_elapsed() {
    let mut f = AcctFacts::default();
    // 1 000 000 s since the epoch, process ran 250 s.
    f.set_btime_from(1_000_000 * 1_000_000_000, 250 * 1_000_000_000);
    assert_eq!(f.btime, 999_750);
    // A lifetime longer than the clock (a clock stepped backwards) clamps at 0
    // rather than wrapping into 2106.
    f.set_btime_from(10 * 1_000_000_000, 999 * 1_000_000_000);
    assert_eq!(f.btime, 0);
}

/// The `acct_on` ladder's ORDER is the whole observable contract of a refusal.
#[test]
fn admission_order_matches_acct_on() {
    let ok = AcctFileFacts { is_regular: true, kernel_internal: false, can_write: true };
    assert_eq!(admit_file(ok), Ok(()));
    // A directory is EACCES even though it is also unwritable — the S_ISREG
    // test runs first.
    assert_eq!(
        admit_file(AcctFileFacts { is_regular: false, kernel_internal: true, can_write: false }),
        Err(AcctFileError::NotRegular));
    // /proc/self/status IS a regular file, so it reaches the pseudo-fs test.
    assert_eq!(
        admit_file(AcctFileFacts { kernel_internal: true, ..ok }),
        Err(AcctFileError::KernelInternal));
    // Only a real, unrestricted, unwritable file reaches EIO.
    assert_eq!(
        admit_file(AcctFileFacts { can_write: false, ..ok }),
        Err(AcctFileError::NotWritable));
}

/// A record for a process killed by a signal carries AXSIG, and one that never
/// exec'd carries AFORK — the two flags `lastcomm` prints.
#[test]
fn exit_flags_ride_the_flag_byte() {
    let mut f = AcctFacts { flag: AXSIG | ACORE, ..Default::default() };
    assert_eq!(f.encode()[0], 0x18);
    f.flag = AFORK | ASU | AGROUP;
    assert_eq!(f.encode()[0], 0x23);
}
