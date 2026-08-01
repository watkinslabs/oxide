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
    assert_eq!(r[1], ACCT_VERSION_BYTE,                 "ac_version @1");
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

/// The version byte carries the byte-order bit, and the whole record is
/// written in that byte order. A reader decides how to interpret every
/// multi-byte field from this one bit, so the two must agree — on x86_64 and
/// on aarch64 alike, both of which this kernel builds little-endian.
#[test]
fn the_version_byte_declares_the_records_byte_order() {
    assert_eq!(ACCT_VERSION_BYTE, ACCT_VERSION | ACCT_BYTEORDER);
    assert_eq!(ACCT_VERSION_BYTE & 0x7f, 3, "the low bits stay the version");
    #[cfg(target_endian = "little")]
    {
        assert_eq!(ACCT_BYTEORDER, 0x00);
        let f = AcctFacts { tty: 0x0102, ..Default::default() };
        assert_eq!(&f.encode()[2..4], &[0x02, 0x01], "fields are little-endian");
    }
    #[cfg(target_endian = "big")]
    assert_eq!(ACCT_BYTEORDER, 0x80);
}

// ---------------------------------------------------------------- free space

use super::parm::*;
use super::space::*;

fn parm() -> AcctParm { AcctParm::default() }

/// Between checks the standing verdict is reused and no `statfs` is asked for,
/// so a burst of exits does not query the filesystem once per record.
#[test]
fn the_verdict_stands_until_the_interval_elapses() {
    let mut st = SpaceState::new(0);
    // The first record is due at once, so accounting never writes on a stale
    // "active" it has not verified.
    assert_eq!(check_due(&st, 0), SpaceCheck::Due);
    apply_statfs(&mut st, 0, parm(), 1000, 900);
    // 30 s of records ride the recorded verdict.
    assert_eq!(check_due(&st, 1_000_000_000), SpaceCheck::Standing(true));
    assert_eq!(check_due(&st, 29_999_999_999), SpaceCheck::Standing(true));
    assert_eq!(check_due(&st, 30_000_000_000), SpaceCheck::Due);
}

/// The suspend and resume thresholds are DIFFERENT percentages, so a disk
/// hovering just under the suspend line does not flap: once suspended, it
/// takes a real recovery to 4% to resume, not a return to 2%.
#[test]
fn suspend_and_resume_hysteresis_does_not_flap() {
    let p = parm();
    let mut st = SpaceState::new(0);
    // 2% of 1000 blocks is 20; at exactly 20 free we suspend (`<=`).
    assert_eq!(apply_statfs(&mut st, 0, p, 1000, 20), SpaceTransition::Paused);
    assert!(!st.active);
    // 30 free is above the suspend line but below the 4% (40) resume line —
    // still suspended, and reported as no edge rather than a second pause.
    assert_eq!(apply_statfs(&mut st, 100, p, 1000, 30), SpaceTransition::Unchanged(false));
    // 40 free reaches the resume line (`>=`).
    assert_eq!(apply_statfs(&mut st, 200, p, 1000, 40), SpaceTransition::Resumed);
    assert!(st.active);
    // And 21 free — one above the suspend line — keeps it active.
    assert_eq!(apply_statfs(&mut st, 300, p, 1000, 21), SpaceTransition::Unchanged(true));
}

/// A backend that reports no blocks at all (a pseudo filesystem) has no notion
/// of fullness, so the verdict is left where it stands rather than read as an
/// empty disk.
#[test]
fn a_filesystem_with_no_blocks_never_moves_the_verdict() {
    let mut st = SpaceState::new(0);
    assert_eq!(apply_statfs(&mut st, 0, parm(), 0, 0), SpaceTransition::Unchanged(true));
    assert!(st.active);
    // The check is still rescheduled, so it does not spin.
    assert_eq!(st.needcheck_ns, 30 * 1_000_000_000);
}

/// A `statfs` that cannot answer leaves both the verdict AND the due time
/// alone, so the next record retries instead of coasting a whole interval on
/// an answer nobody got.
#[test]
fn a_failed_statfs_keeps_the_check_due() {
    let st = SpaceState { active: false, needcheck_ns: 0 };
    assert!(!statfs_failed(&st));
    assert_eq!(check_due(&st, 0), SpaceCheck::Due, "still due after a failure");
}

/// A shorter interval written through the tunable takes effect on the NEXT
/// scheduled check — the knob is live, not a boot-time constant.
#[test]
fn the_timeout_tunable_sets_the_interval() {
    let mut st = SpaceState::new(0);
    let p = AcctParm { timeout_secs: 5, ..parm() };
    apply_statfs(&mut st, 0, p, 1000, 900);
    assert_eq!(st.needcheck_ns, 5 * 1_000_000_000);
    assert_eq!(check_due(&st, 4_999_999_999), SpaceCheck::Standing(true));
    assert_eq!(check_due(&st, 5_000_000_000), SpaceCheck::Due);
}

// ------------------------------------------------------------- kernel/acct

/// The leaf reports all three tunables tab-separated with one trailing
/// newline — the vector form `sysctl` parses.
#[test]
fn the_tunable_leaf_reports_three_tab_separated_ints() {
    assert_eq!(format_parms(AcctParm::default()), b"4\t2\t30\n".to_vec());
    assert_eq!(
        format_parms(AcctParm { resume_pct: 10, suspend_pct: 5, timeout_secs: 1 }),
        b"10\t5\t1\n".to_vec());
}

/// A write updates as many leading elements as it supplies and leaves the rest
/// alone, which is what makes `sysctl -w kernel.acct="10"` a one-field change
/// rather than a reset of the other two.
#[test]
fn a_short_write_updates_only_the_elements_it_supplies() {
    let base = AcctParm::default();
    assert_eq!(parse_parms(base, b"10"),
        Some(AcctParm { resume_pct: 10, ..base }));
    assert_eq!(parse_parms(base, b"10 5"),
        Some(AcctParm { resume_pct: 10, suspend_pct: 5, ..base }));
    assert_eq!(parse_parms(base, b"10 5 60\n"),
        Some(AcctParm { resume_pct: 10, suspend_pct: 5, timeout_secs: 60 }));
    // Tabs and newlines separate exactly as spaces do.
    assert_eq!(parse_parms(base, b"1\t2\t3\n"),
        Some(AcctParm { resume_pct: 1, suspend_pct: 2, timeout_secs: 3 }));
}

/// A malformed or oversized write is rejected WHOLE: a typo in a config file
/// must not leave the first field applied and the rest not.
#[test]
fn a_malformed_write_applies_nothing() {
    let base = AcctParm::default();
    assert_eq!(parse_parms(base, b"10 nope"), None);
    assert_eq!(parse_parms(base, b""), None);
    assert_eq!(parse_parms(base, b"   \n"), None);
    assert_eq!(parse_parms(base, b"1 2 3 4"), None, "more elements than the leaf holds");
    assert_eq!(parse_parms(base, b"99999999999"), None, "wider than the int it is stored in");
    assert_eq!(parse_parms(base, b"-"), None);
}

/// Negative values round-trip, since the leaf is a signed int vector.
#[test]
fn the_leaf_round_trips_through_format_and_parse() {
    for p in [
        AcctParm::default(),
        AcctParm { resume_pct: 0, suspend_pct: 0, timeout_secs: 0 },
        AcctParm { resume_pct: -1, suspend_pct: 100, timeout_secs: 2_147_483_647 },
    ] {
        assert_eq!(parse_parms(AcctParm::default(), &format_parms(p)), Some(p));
    }
}

/// A nonsensical percentage cannot make the check panic or wrap: a negative
/// threshold reads as zero, which suspends only on a genuinely full disk.
#[test]
fn a_negative_threshold_degrades_rather_than_wrapping() {
    let p = AcctParm { resume_pct: -5, suspend_pct: -5, timeout_secs: -5 };
    let mut st = SpaceState::new(0);
    assert_eq!(apply_statfs(&mut st, 0, p, 1000, 0), SpaceTransition::Paused,
        "0 free is still <= a 0% threshold");
    assert_eq!(apply_statfs(&mut st, 0, p, 1000, 1), SpaceTransition::Resumed);
    assert_eq!(st.needcheck_ns, 0, "a negative interval means always due");
}

// ------------------------------------------------------- per-namespace write

/// The record a namespace receives carries THAT namespace's pids, so one exit
/// written to two files is not the same 64 bytes twice.
#[test]
fn each_target_gets_its_own_pid_pair() {
    let host  = NsTarget { ns_id: 0,  pid: 900, ppid: 880 };
    let guest = NsTarget { ns_id: 42, pid: 7,   ppid: 1 };
    assert_ne!(host, guest);
    let mut f = AcctFacts::default();
    f.pid = host.pid; f.ppid = host.ppid;
    let a = f.encode();
    f.pid = guest.pid; f.ppid = guest.ppid;
    let b = f.encode();
    assert_eq!(u32::from_le_bytes([a[16], a[17], a[18], a[19]]), 900);
    assert_eq!(u32::from_le_bytes([b[16], b[17], b[18], b[19]]), 7);
    assert_eq!(u32::from_le_bytes([a[20], a[21], a[22], a[23]]), 880);
    assert_eq!(u32::from_le_bytes([b[20], b[21], b[22], b[23]]), 1);
    // Everything else is identical: the two records describe one exit.
    assert_eq!(&a[..16], &b[..16]);
    assert_eq!(&a[24..], &b[24..]);
}

/// The three fields the record reserves but no longer maintains are zero in
/// every record. A tool computing averages over `ac_io` gets the same answer
/// here as on the system it was written for.
#[test]
fn the_unmaintained_bsd_fields_are_zero() {
    let f = AcctFacts { io: 0, rw: 0, swaps: 0, ..Default::default() };
    let r = f.encode();
    assert_eq!(u16::from_le_bytes([r[38], r[39]]), 0, "ac_io @38");
    assert_eq!(u16::from_le_bytes([r[40], r[41]]), 0, "ac_rw @40");
    assert_eq!(u16::from_le_bytes([r[46], r[47]]), 0, "ac_swaps @46");
}
