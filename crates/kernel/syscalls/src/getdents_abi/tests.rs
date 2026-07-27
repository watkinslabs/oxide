// Hosted unit tests for the getdents record ABI + fill accounting. These are
// the rules that regressed silently: the slot file is
// `#![cfg(target_os = "oxide-kernel")]`, so every byte-offset and every errno
// in the return rule was unreachable from `cargo test`.
// Reference: Linux `fs/readdir.c` + `include/linux/dirent.h` (v7.2.0-rc4).

use super::*;
use alloc::vec;
use alloc::vec::Vec;

const DT_REG: u8 = 8;
const DT_DIR: u8 = 4;
const DT_LNK: u8 = 10;

// --- record layout, byte for byte -----------------------------------------

/// `linux_dirent64`: d_ino@0, d_off@8, d_reclen@16, d_type@18, d_name@19.
#[test]
fn dirent64_record_is_byte_exact() {
    let mut buf = [0xAAu8; 64];
    let n = write_record(&mut buf, DirentLayout::Modern, 0x1122_3344_5566_7788,
                         0x0102_0304_0506_0708, DT_LNK, b"passwd").unwrap();
    assert_eq!(n, 32, "19 header + 6 name + NUL = 26 -> ALIGN 8 = 32");
    assert_eq!(u64::from_le_bytes(buf[0..8].try_into().unwrap()), 0x1122_3344_5566_7788);
    assert_eq!(u64::from_le_bytes(buf[8..16].try_into().unwrap()), 0x0102_0304_0506_0708);
    assert_eq!(u16::from_le_bytes(buf[16..18].try_into().unwrap()) as usize, n);
    assert_eq!(buf[18], DT_LNK, "d_type is a real field at offset 18");
    assert_eq!(&buf[19..25], b"passwd");
    assert_eq!(&buf[25..32], &[0u8; 7], "NUL + pad, no stale bytes leaked");
    assert_eq!(buf[32], 0xAA, "nothing written past d_reclen");
}

/// Legacy `linux_dirent`: d_ino@0, d_off@8, d_reclen@16, d_name@18, and
/// d_type in the record's LAST byte. Putting d_type at 18 (the dirent64
/// position) would overwrite the name's first character.
#[test]
fn legacy_dirent_record_is_byte_exact() {
    let mut buf = [0xAAu8; 64];
    let n = write_record(&mut buf, DirentLayout::Legacy, 0x42, 0x7, DT_DIR, b"dev").unwrap();
    assert_eq!(n, 24, "18 header + 3 name + NUL + d_type = 23 -> ALIGN 8 = 24");
    assert_eq!(u64::from_le_bytes(buf[0..8].try_into().unwrap()), 0x42);
    assert_eq!(u64::from_le_bytes(buf[8..16].try_into().unwrap()), 0x7);
    assert_eq!(u16::from_le_bytes(buf[16..18].try_into().unwrap()) as usize, n);
    assert_eq!(&buf[18..21], b"dev", "name starts at 18, one byte earlier than dirent64");
    assert_eq!(buf[21], 0, "name NUL-terminated");
    assert_eq!(&buf[22..23], &[0u8], "pad");
    assert_eq!(buf[n - 1], DT_DIR, "d_type at d_reclen - 1");
    assert_eq!(buf[n], 0xAA, "nothing written past d_reclen");
}

/// The two layouts differ: same name, same reclen here, but d_type and the
/// name sit at different offsets. A shim that packs one and claims the other
/// hands userspace a record whose name is off by one byte.
#[test]
fn the_two_layouts_are_not_interchangeable() {
    let mut a = [0u8; 64];
    let mut b = [0u8; 64];
    write_record(&mut a, DirentLayout::Legacy, 1, 1, DT_REG, b"x").unwrap();
    write_record(&mut b, DirentLayout::Modern, 1, 1, DT_REG, b"x").unwrap();
    assert_ne!(a[..24], b[..24]);
    assert_eq!(a[18], b'x');
    assert_eq!(b[18], DT_REG);
    assert_eq!(b[19], b'x');
}

/// `ALIGN(offsetof(d_name[namlen + 2]), sizeof(long))` /
/// `ALIGN(offsetof(d_name[namlen + 1]), sizeof(u64))`. On LP64 the two
/// formulas coincide, and both must always leave room for the NUL (and, for
/// the legacy layout, the trailing d_type byte).
#[test]
fn reclen_matches_linux_align_formula() {
    for len in 1..=300usize {
        let legacy = DirentLayout::Legacy.reclen(len);
        let modern = DirentLayout::Modern.reclen(len);
        assert_eq!(legacy, (DIRENT_NAME_OFF + len + 2 + 7) & !7);
        assert_eq!(modern, (DIRENT64_NAME_OFF + len + 1 + 7) & !7);
        assert_eq!(legacy % 8, 0);
        assert_eq!(modern % 8, 0);
        assert_eq!(legacy, modern, "the +2/+1 and the 18/19 header cancel on LP64");
        // The legacy d_type byte must never land inside the name or its NUL.
        assert!(DirentLayout::Legacy.dtype_off(legacy) > DIRENT_NAME_OFF + len);
    }
}

/// A caller walks the buffer by `d_reclen`. Pack a run of records with mixed
/// name lengths and re-walk it: every record must land exactly where the
/// previous one's `d_reclen` said it would, with no drift.
#[test]
fn buffer_walks_by_d_reclen_without_drift() {
    for layout in [DirentLayout::Legacy, DirentLayout::Modern] {
        let names: [&[u8]; 6] = [b".", b"..", b"a", b"bb", b"ccccccc", b"dddddddddddddddd"];
        let mut buf = vec![0u8; 512];
        let mut at = 0usize;
        for (i, n) in names.iter().enumerate() {
            at += write_record(&mut buf[at..], layout, i as u64 + 1, i as u64 + 1,
                               DT_REG, n).unwrap();
        }
        let total = at;
        let mut p = 0usize;
        let mut seen: Vec<Vec<u8>> = Vec::new();
        while p < total {
            let reclen = u16::from_le_bytes(buf[p + 16..p + 18].try_into().unwrap()) as usize;
            assert_ne!(reclen, 0, "a zero d_reclen wedges the caller's loop forever");
            let no = p + layout.name_off();
            let end = no + buf[no..p + reclen].iter().position(|&b| b == 0).unwrap();
            seen.push(buf[no..end].to_vec());
            p += reclen;
        }
        assert_eq!(p, total, "reclen chain lands exactly on the end of the packed run");
        let want: Vec<Vec<u8>> = names.iter().map(|n| n.to_vec()).collect();
        assert_eq!(seen, want);
    }
}

/// The `d_type` byte survives the walk for every DT_* value, in both layouts.
#[test]
fn d_type_round_trips_in_both_layouts() {
    for layout in [DirentLayout::Legacy, DirentLayout::Modern] {
        for dt in [0u8, 1, 2, 4, 6, 8, 10, 12] {
            let mut buf = [0u8; 64];
            let n = write_record(&mut buf, layout, 9, 9, dt, b"name").unwrap();
            assert_eq!(buf[layout.dtype_off(n)], dt);
        }
    }
}

// --- verify_dirent_name ----------------------------------------------------

/// Linux `verify_dirent_name`: empty, `>= PATH_MAX`, or containing `/` is
/// filesystem corruption and the walk stops with EIO.
#[test]
fn name_verification_matches_linux() {
    assert_eq!(verify_dirent_name(b"ok"), Ok(()));
    assert_eq!(verify_dirent_name(b".."), Ok(()));
    assert_eq!(verify_dirent_name(b""), Err(Errno::Eio));
    assert_eq!(verify_dirent_name(b"a/b"), Err(Errno::Eio));
    assert_eq!(verify_dirent_name(b"/"), Err(Errno::Eio));
    assert_eq!(verify_dirent_name(&vec![b'x'; PATH_MAX - 1]), Ok(()));
    assert_eq!(verify_dirent_name(&vec![b'x'; PATH_MAX]), Err(Errno::Eio));
}

/// The widest record `verify_dirent_name` can admit still fits `MAX_RECLEN`,
/// so a corrupt directory block cannot overrun a caller sized by that bound.
#[test]
fn max_reclen_bounds_every_admissible_name() {
    let longest = PATH_MAX - 1;
    assert!(verify_dirent_name(&vec![b'x'; longest]).is_ok());
    assert!(DirentLayout::Legacy.reclen(longest) <= MAX_RECLEN);
    assert!(DirentLayout::Modern.reclen(longest) <= MAX_RECLEN);
}

/// A name that fails verification stops the walk with EIO and writes nothing.
#[test]
fn corrupt_name_stops_with_eio_not_a_torn_record() {
    let mut fill = DirentFill::new(DirentLayout::Modern, 256);
    let mut out = [0u8; 256];
    assert_eq!(fill.offer(&mut out, 1, 1, DT_REG, b"good"), Fill::Wrote(24));
    assert_eq!(fill.offer(&mut out, 2, 2, DT_REG, b"ba/d"), Fill::Stop);
    assert_eq!(fill.error(), Some(Errno::Eio));
    assert_eq!(fill.written(), 24, "the corrupt entry consumed no buffer");
    // Bytes already packed still win: the caller gets the good entry.
    assert_eq!(fill.ret(None), 24);
}

// --- fill accounting + the return rule -------------------------------------

/// A buffer too small for even the FIRST record is EINVAL, never a short read
/// and never 0 — a caller reading 0 would stop, silently truncating the
/// listing.
#[test]
fn buffer_too_small_for_one_entry_is_einval() {
    let name = b"averylongfilename";
    let need = DirentLayout::Modern.reclen(name.len());
    let mut fill = DirentFill::new(DirentLayout::Modern, need - 8);
    let mut out = vec![0u8; need];
    assert_eq!(fill.offer(&mut out, 1, 1, DT_REG, name), Fill::Stop);
    assert_eq!(fill.written(), 0);
    assert_eq!(fill.ret(None), -(Errno::Einval.as_i32() as i64));
}

/// An empty directory is 0 (end-of-directory), NOT EINVAL — nothing was ever
/// offered, so no capacity test ever parked an error.
#[test]
fn empty_directory_returns_zero() {
    let fill = DirentFill::new(DirentLayout::Modern, 4096);
    assert_eq!(fill.written(), 0);
    assert_eq!(fill.error(), None);
    assert_eq!(fill.ret(None), 0);
}

/// `count == 0` on a non-empty directory is EINVAL, matching the too-small
/// case; on an empty directory it is still 0.
#[test]
fn zero_count_is_einval_only_when_an_entry_exists() {
    let mut fill = DirentFill::new(DirentLayout::Modern, 0);
    let mut out: [u8; 0] = [];
    assert_eq!(fill.offer(&mut out, 1, 1, DT_REG, b"x"), Fill::Stop);
    assert_eq!(fill.ret(None), -(Errno::Einval.as_i32() as i64));

    let empty = DirentFill::new(DirentLayout::Modern, 0);
    assert_eq!(empty.ret(None), 0);
}

/// The buffer fills exactly: the last record that fits is written, the next is
/// refused, and the byte count is returned rather than the parked EINVAL.
#[test]
fn exact_fit_then_overflow_returns_bytes_not_einval() {
    let r = DirentLayout::Modern.reclen(4);
    let mut fill = DirentFill::new(DirentLayout::Modern, r * 2);
    let mut out = vec![0u8; r * 2];
    assert_eq!(fill.offer(&mut out, 1, 1, DT_REG, b"aaaa"), Fill::Wrote(r));
    assert_eq!(fill.offer(&mut out, 2, 2, DT_REG, b"bbbb"), Fill::Wrote(r));
    assert_eq!(fill.offer(&mut out, 3, 3, DT_REG, b"cccc"), Fill::Stop);
    assert_eq!(fill.error(), Some(Errno::Einval), "Linux parks EINVAL on every capacity test");
    assert_eq!(fill.ret(None), (r * 2) as i64, "bytes win over the parked EINVAL");
}

/// Linux's tail (`if (buf.prev_reclen) error = count - ctx.count;`): bytes
/// already packed win over a LATE backend error. Returning the errno instead
/// would throw away entries the caller can already use, and `ls` would report
/// a failure for a directory it had just read.
#[test]
fn bytes_already_written_win_over_a_late_backend_error() {
    let mut fill = DirentFill::new(DirentLayout::Modern, 4096);
    let mut out = vec![0u8; 4096];
    let n = match fill.offer(&mut out, 1, 1, DT_REG, b"first") { Fill::Wrote(n) => n, _ => panic!() };
    assert_eq!(fill.ret(Some(Errno::Eio.as_i32())), n as i64);
}

/// With nothing written, the ITERATE error wins over the parked fill error —
/// Linux's `if (error >= 0) error = buf.error;` only consults `buf.error`
/// when `iterate_dir` succeeded.
#[test]
fn iterate_error_wins_when_nothing_was_written() {
    let mut fill = DirentFill::new(DirentLayout::Modern, 8);
    let mut out = [0u8; 8];
    assert_eq!(fill.offer(&mut out, 1, 1, DT_REG, b"toolong"), Fill::Stop);
    assert_eq!(fill.error(), Some(Errno::Einval));
    assert_eq!(fill.ret(Some(Errno::Eio.as_i32())), -(Errno::Eio.as_i32() as i64));
}

/// `d_off` is the caller's resume cookie: pack a paginated run, then re-run
/// from the last record's `d_off` and assert the suffix follows with no
/// duplicate and no skip. This is the `telldir`/`seekdir` contract.
#[test]
fn d_off_cookie_resumes_exactly_after_the_last_record() {
    // (name, cookie-of-next-position) as a backend emits them.
    let dir: [(&[u8], u64); 5] = [(b"alpha", 1), (b"bravo", 2), (b"charlie", 3),
                                  (b"delta", 4), (b"echo", 5)];
    let page = DirentLayout::Modern.reclen(5) + DirentLayout::Modern.reclen(5);

    let mut fill = DirentFill::new(DirentLayout::Modern, page);
    let mut out = vec![0u8; page];
    let mut resume = 0u64;
    for (name, next) in dir.iter() {
        match fill.offer(&mut out, 1, *next, DT_REG, name) {
            Fill::Wrote(_) => resume = *next,
            Fill::Stop => break,
        }
    }
    let first: Vec<Vec<u8>> = walk(&out[..fill.written()], DirentLayout::Modern);
    assert_eq!(first, vec![b"alpha".to_vec(), b"bravo".to_vec()]);
    // The last record's d_off is the cookie the next call resumes from.
    let last_off = last_d_off(&out[..fill.written()], DirentLayout::Modern);
    assert_eq!(last_off, resume);
    assert_eq!(resume, 2);

    let mut fill2 = DirentFill::new(DirentLayout::Modern, 4096);
    let mut out2 = vec![0u8; 4096];
    for (name, next) in dir.iter().skip(resume as usize) {
        assert!(matches!(fill2.offer(&mut out2, 1, *next, DT_REG, name), Fill::Wrote(_)));
    }
    let second = walk(&out2[..fill2.written()], DirentLayout::Modern);
    assert_eq!(second, vec![b"charlie".to_vec(), b"delta".to_vec(), b"echo".to_vec()],
               "resume yields the exact suffix: no replay, no skip");
}

/// A pending signal abandons the walk only once something is packed — with an
/// empty buffer Linux keeps going, so a signal can never turn a first call
/// into a spurious 0 that reads as end-of-directory.
#[test]
fn signal_stops_the_fill_only_after_the_first_record() {
    assert!(!interrupt_stops_fill(0, true), "no record yet: keep going");
    assert!(!interrupt_stops_fill(64, false));
    assert!(interrupt_stops_fill(64, true));
}

/// Linux's `count` parameter is `unsigned int`: the register argument is
/// truncated, so a 4 GiB-plus count is not honoured as-is.
#[test]
fn count_argument_is_truncated_to_unsigned_int() {
    assert_eq!(count_arg(0), 0);
    assert_eq!(count_arg(4096), 4096);
    assert_eq!(count_arg(u32::MAX as u64), u32::MAX as usize);
    assert_eq!(count_arg(1u64 << 32), 0);
    assert_eq!(count_arg((1u64 << 32) + 8), 8);
}

// --- helpers ---------------------------------------------------------------

fn walk(buf: &[u8], layout: DirentLayout) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p < buf.len() {
        let reclen = u16::from_le_bytes(buf[p + 16..p + 18].try_into().unwrap()) as usize;
        let no = p + layout.name_off();
        let end = no + buf[no..p + reclen].iter().position(|&b| b == 0).unwrap();
        out.push(buf[no..end].to_vec());
        p += reclen;
    }
    out
}

fn last_d_off(buf: &[u8], _layout: DirentLayout) -> u64 {
    let mut p = 0usize;
    let mut last = 0u64;
    while p < buf.len() {
        let reclen = u16::from_le_bytes(buf[p + 16..p + 18].try_into().unwrap()) as usize;
        last = u64::from_le_bytes(buf[p + 8..p + 16].try_into().unwrap());
        p += reclen;
    }
    last
}

/// Linux rewrites the LAST record's `d_off` with the final `ctx->pos` before
/// returning, so `telldir(3)` right after the last entry yields the
/// end-of-directory position rather than a cookie just past that record.
#[test]
fn the_last_records_d_off_is_sealed_with_the_final_position() {
    let mut fill = DirentFill::new(DirentLayout::Modern, 4096);
    let mut out = vec![0u8; 4096];
    fill.offer(&mut out, 1, 10, DT_REG, b"a");
    fill.offer(&mut out, 2, 20, DT_REG, b"b");
    let before = walk_offs(&out[..fill.written()]);
    assert_eq!(before, vec![10, 20]);

    assert!(fill.seal_last_d_off(&mut out, 4096));
    let after = walk_offs(&out[..fill.written()]);
    assert_eq!(after, vec![10, 4096], "only the last record is rewritten");
}

/// Sealing an empty buffer is a no-op success — nothing was written, so there
/// is no last record.
#[test]
fn sealing_an_empty_fill_writes_nothing() {
    let fill = DirentFill::new(DirentLayout::Modern, 64);
    let mut out = [0xEEu8; 64];
    assert!(fill.seal_last_d_off(&mut out, 99));
    assert_eq!(out, [0xEEu8; 64]);
}

fn walk_offs(buf: &[u8]) -> Vec<u64> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p < buf.len() {
        let reclen = u16::from_le_bytes(buf[p + 16..p + 18].try_into().unwrap()) as usize;
        out.push(u64::from_le_bytes(buf[p + 8..p + 16].try_into().unwrap()));
        p += reclen;
    }
    out
}
