// Wire codec: every primitive and composite body, encode then decode.

extern crate alloc;
use alloc::vec::Vec;

use crate::codec::*;
use crate::err::NpError;
use crate::uapi::{limits, op, qid as qidbits};

fn enc() -> Enc { Enc::request(op::TVERSION, 0x1234, 64 * 1024) }

#[test]
fn integers_are_little_endian() {
    let mut e = enc();
    e.u8(0xAB).unwrap();
    e.u16(0x1122).unwrap();
    e.u32(0x1122_3344).unwrap();
    e.u64(0x1122_3344_5566_7788).unwrap();
    let f = e.finish().unwrap();
    assert_eq!(&f[limits::HDRSZ..], &[
        0xAB,
        0x22, 0x11,
        0x44, 0x33, 0x22, 0x11,
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    ]);
    let mut d = Dec::new(&f[limits::HDRSZ..]);
    assert_eq!(d.u8().unwrap(), 0xAB);
    assert_eq!(d.u16().unwrap(), 0x1122);
    assert_eq!(d.u32().unwrap(), 0x1122_3344);
    assert_eq!(d.u64().unwrap(), 0x1122_3344_5566_7788);
    assert!(d.at_end());
}

#[test]
fn header_is_size_type_tag() {
    let e = enc();
    let f = e.finish().unwrap();
    assert_eq!(f.len(), limits::HDRSZ);
    let (h, body) = split_header(&f).unwrap();
    assert_eq!(h.size as usize, limits::HDRSZ);
    assert_eq!(h.ty, op::TVERSION);
    assert_eq!(h.tag, 0x1234);
    assert!(body.is_empty());
    // The size field is the FIRST four bytes, little-endian.
    assert_eq!(&f[..4], &(limits::HDRSZ as u32).to_le_bytes());
    assert_eq!(f[4], op::TVERSION);
    assert_eq!(&f[5..7], &0x1234u16.to_le_bytes());
}

#[test]
fn a_declared_size_that_disagrees_with_the_frame_is_rejected() {
    let mut e = enc();
    e.u32(7).unwrap();
    let mut f = e.finish().unwrap();
    // Under-declare: a server hiding trailing bytes from the body decoder.
    f[0] = f[0].wrapping_sub(1);
    assert_eq!(split_header(&f).unwrap_err(), NpError::BadMessage);
    // Over-declare: a truncated frame that claims to be whole.
    f[0] = f[0].wrapping_add(2);
    assert_eq!(split_header(&f).unwrap_err(), NpError::BadMessage);
    // A frame shorter than the header at all.
    assert_eq!(split_header(&[0u8; 6]).unwrap_err(), NpError::BadMessage);
}

#[test]
fn peek_size_needs_four_bytes() {
    assert_eq!(peek_size(&[1, 2, 3]), None);
    assert_eq!(peek_size(&[0x11, 0x22, 0x33, 0x44, 0x55]), Some(0x4433_2211));
}

#[test]
fn strings_carry_a_sixteen_bit_byte_count() {
    let mut e = enc();
    e.string("hello").unwrap();
    e.string("").unwrap();
    let f = e.finish().unwrap();
    let body = &f[limits::HDRSZ..];
    assert_eq!(&body[..2], &5u16.to_le_bytes());
    assert_eq!(&body[2..7], b"hello");
    assert_eq!(&body[7..9], &0u16.to_le_bytes());
    let mut d = Dec::new(body);
    assert_eq!(d.string().unwrap(), "hello");
    assert_eq!(d.string().unwrap(), "");
}

#[test]
fn a_non_utf8_name_fails_rather_than_being_mangled() {
    let mut e = enc();
    e.bytes_str(&[0xFF, 0xFE]).unwrap();
    let f = e.finish().unwrap();
    let mut d = Dec::new(&f[limits::HDRSZ..]);
    assert_eq!(d.string().unwrap_err(), NpError::BadMessage);
    let mut d = Dec::new(&f[limits::HDRSZ..]);
    assert_eq!(d.bytes_str().unwrap(), &[0xFF, 0xFE]);
}

#[test]
fn a_truncated_read_is_an_error_not_a_zero() {
    let f = [0u8; 3];
    let mut d = Dec::new(&f);
    assert_eq!(d.u32().unwrap_err(), NpError::BadMessage);
    let mut d = Dec::new(&f);
    assert_eq!(d.u16().unwrap(), 0);
    assert_eq!(d.u16().unwrap_err(), NpError::BadMessage);
}

#[test]
fn qid_is_thirteen_bytes_type_version_path() {
    let q = Qid { ty: qidbits::QTDIR, version: 0xDEAD_BEEF, path: 0x0102_0304_0506_0708 };
    let mut e = enc();
    e.qid(&q).unwrap();
    let f = e.finish().unwrap();
    let body = &f[limits::HDRSZ..];
    assert_eq!(body.len(), limits::QID_SZ);
    assert_eq!(body[0], qidbits::QTDIR);
    assert_eq!(&body[1..5], &0xDEAD_BEEFu32.to_le_bytes());
    assert_eq!(&body[5..13], &0x0102_0304_0506_0708u64.to_le_bytes());
    assert_eq!(Dec::new(body).qid().unwrap(), q);
    assert!(q.is_dir());
    assert!(!q.is_symlink());
    assert!(q.is_cacheable());
    assert!(!Qid { version: 0, ..q }.is_cacheable());
}

#[test]
fn data_clamps_an_over_declared_count() {
    // `count[4]` then the payload. A server declaring more than it sent must
    // not make the decode fail after the bytes it did send were usable.
    let mut buf = alloc::vec::Vec::new();
    buf.extend_from_slice(&99u32.to_le_bytes());
    buf.extend_from_slice(b"abc");
    let mut d = Dec::new(&buf);
    assert_eq!(d.data().unwrap(), b"abc");
}

#[test]
fn dirent_stream_decodes_every_entry_and_rejects_a_partial_tail() {
    let mut e = Enc::request(0, 0, 4096);
    let entries = [
        DirEntry { qid: Qid { ty: qidbits::QTDIR, version: 1, path: 2 }, offset: 1, dtype: 4, name: b"sub" },
        DirEntry { qid: Qid { ty: qidbits::QTFILE, version: 3, path: 4 }, offset: 2, dtype: 8, name: b"f.txt" },
    ];
    for ent in &entries { encode_dirent(&mut e, ent).unwrap(); }
    let f = e.finish().unwrap();
    let payload = &f[limits::HDRSZ..];
    let got: Vec<DirEntry<'_>> = DirEntries::new(payload).map(|r| r.unwrap()).collect();
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].name, b"sub");
    assert_eq!(got[0].offset, 1);
    assert_eq!(got[1].qid.path, 4);
    assert_eq!(got[1].dtype, 8);
    // Chopping the last name prefix must be reported, not silently dropped.
    let short = &payload[..payload.len() - 2];
    let last = DirEntries::new(short).last().unwrap();
    assert!(last.is_err());
}

#[test]
fn getattr_body_round_trips_every_field() {
    let st = StatDotl {
        valid: 0x3fff,
        qid: Qid { ty: 0x80, version: 9, path: 10 },
        mode: 0o40755, uid: 1000, gid: 1001,
        nlink: 3, rdev: 0, size: 4096, blksize: 512, blocks: 8,
        atime_sec: 11, atime_nsec: 12, mtime_sec: 13, mtime_nsec: 14,
        ctime_sec: 15, ctime_nsec: 16, btime_sec: 17, btime_nsec: 18,
        gen: 19, data_version: 20,
    };
    let mut e = enc();
    st.encode(&mut e).unwrap();
    let f = e.finish().unwrap();
    let body = &f[limits::HDRSZ..];
    assert_eq!(body.len(), limits::GETATTR_BODY_SZ);
    assert_eq!(StatDotl::decode(&mut Dec::new(body)).unwrap(), st);
    assert!(st.has(crate::uapi::stats::SIZE));
    assert!(!StatDotl { valid: 0, ..st }.has(crate::uapi::stats::SIZE));
}

#[test]
fn setattr_body_round_trips_and_has_the_declared_width() {
    let a = IattrDotl {
        valid: 0x1ff, mode: 0o644, uid: 5, gid: 6, size: 7,
        atime_sec: 8, atime_nsec: 9, mtime_sec: 10, mtime_nsec: 11,
    };
    let mut e = enc();
    a.encode(&mut e).unwrap();
    let f = e.finish().unwrap();
    let body = &f[limits::HDRSZ..];
    assert_eq!(body.len(), limits::SETATTR_BODY_SZ);
    assert_eq!(IattrDotl::decode(&mut Dec::new(body)).unwrap(), a);
}

#[test]
fn statfs_body_round_trips_and_has_the_declared_width() {
    let s = StatFs { ty: 1, bsize: 2, blocks: 3, bfree: 4, bavail: 5,
                     files: 6, ffree: 7, fsid: 8, namelen: 9 };
    let mut e = enc();
    s.encode(&mut e).unwrap();
    let f = e.finish().unwrap();
    let body = &f[limits::HDRSZ..];
    assert_eq!(body.len(), limits::STATFS_BODY_SZ);
    assert_eq!(StatFs::decode(&mut Dec::new(body)).unwrap(), s);
}

#[test]
fn getlock_round_trips() {
    let g = GetLock { ty: 1, start: 100, length: 0, proc_id: 42, client_id: "oxide-1" };
    let mut e = enc();
    g.encode(&mut e).unwrap();
    let f = e.finish().unwrap();
    assert_eq!(GetLock::decode(&mut Dec::new(&f[limits::HDRSZ..])).unwrap(), g);
}

#[test]
fn a_wstat_size_field_excludes_itself_and_the_dialect_gates_the_extension() {
    let st = Wstat {
        ty: 1, dev: 2, qid: Qid { ty: 0, version: 3, path: 4 },
        mode: 0o644, atime: 5, mtime: 6, length: 7,
        name: "f", uid: "u", gid: "g", muid: "m",
        extension: "ext", n_uid: 8, n_gid: 9, n_muid: 10,
    };
    for dialect in [Dialect::Legacy, Dialect::DotU, Dialect::DotL] {
        let mut e = enc();
        st.encode(&mut e, dialect).unwrap();
        let f = e.finish().unwrap();
        let body = &f[limits::HDRSZ..];
        let declared = u16::from_le_bytes([body[0], body[1]]) as usize;
        // The field counts everything AFTER itself.
        assert_eq!(declared, body.len() - 2, "{dialect:?}");
        assert_eq!(declared, st.body_len(dialect), "{dialect:?}");
        let back = Wstat::decode(&mut Dec::new(body), dialect).unwrap();
        if dialect.has_unix_ext() {
            assert_eq!(back, st, "{dialect:?}");
        } else {
            // Base 9P2000 has no extension block on the wire at all.
            assert_eq!(back.extension, "");
            assert_eq!(back.n_uid, DONT_TOUCH_U32);
            assert_eq!(back.name, "f");
        }
    }
    // The extension block is exactly the size difference between dialects.
    assert_eq!(st.body_len(Dialect::DotU) - st.body_len(Dialect::Legacy),
               2 + "ext".len() + 4 + 4 + 4);
}

#[test]
fn a_blank_wstat_changes_nothing() {
    let b = Wstat::blank();
    assert_eq!(b.mode, DONT_TOUCH_U32);
    assert_eq!(b.length, DONT_TOUCH_U64);
    assert_eq!(b.ty, DONT_TOUCH_U16);
    assert_eq!(b.name, "");
}

#[test]
fn dialect_strings_round_trip_and_gate_the_right_features() {
    for d in [Dialect::Legacy, Dialect::DotU, Dialect::DotL] {
        assert_eq!(Dialect::parse(d.as_str()), Some(d));
    }
    assert_eq!(Dialect::parse("9P2000.z"), None);
    assert!(!Dialect::Legacy.has_unix_ext());
    assert!(Dialect::DotU.has_unix_ext());
    assert!(Dialect::DotL.has_unix_ext());
    assert!(Dialect::DotL.numeric_errors());
    assert!(!Dialect::DotU.numeric_errors());
}

#[test]
fn plan9_modes_translate_to_posix_types() {
    use crate::uapi::dm;
    assert_eq!(p9mode_to_posix(dm::DMDIR | 0o755, Dialect::DotL, false), 0o40755);
    assert_eq!(p9mode_to_posix(0o644, Dialect::DotL, false), 0o100644);
    assert_eq!(p9mode_to_posix(dm::DMSYMLINK | 0o777, Dialect::DotU, false), 0o120777);
    // `nodevmap` refuses to materialise a device class the server reported.
    assert_eq!(p9mode_to_posix(dm::DMSOCKET | 0o666, Dialect::DotU, true), 0o100666);
    assert_eq!(p9mode_to_posix(dm::DMSOCKET | 0o666, Dialect::DotU, false), 0o140666);
    // A legacy server has no extension bits at all; they must not be read.
    assert_eq!(p9mode_to_posix(dm::DMSYMLINK | 0o777, Dialect::Legacy, false), 0o100777);
    assert_eq!(p9mode_to_posix(dm::DMSETUID | 0o755, Dialect::DotU, false), 0o104755);
}

#[test]
fn every_reply_opcode_is_its_request_plus_one() {
    for t in [op::TSTATFS, op::TLOPEN, op::TLCREATE, op::TSYMLINK, op::TMKNOD,
              op::TRENAME, op::TREADLINK, op::TGETATTR, op::TSETATTR, op::TXATTRWALK,
              op::TXATTRCREATE, op::TREADDIR, op::TFSYNC, op::TLOCK, op::TGETLOCK,
              op::TLINK, op::TMKDIR, op::TRENAMEAT, op::TUNLINKAT, op::TVERSION,
              op::TAUTH, op::TATTACH, op::TFLUSH, op::TWALK, op::TOPEN, op::TCREATE,
              op::TREAD, op::TWRITE, op::TCLUNK, op::TREMOVE, op::TSTAT, op::TWSTAT] {
        assert_eq!(op::reply_of(t), t + 1, "opcode {t}");
        // Every request opcode is even and every reply odd, which is what makes
        // the `+1` rule unambiguous.
        assert_eq!(t % 2, 0, "opcode {t}");
    }
    // The two error replies have no request and are odd like any other reply.
    assert_eq!(op::RLERROR % 2, 1);
    assert_eq!(op::RERROR % 2, 1);
}

#[test]
fn a_malformed_dirent_stream_ends_instead_of_repeating_its_error() {
    // The cursor cannot advance past bytes it could not decode, so without a
    // latch the iterator yields the same error forever and every drain of it —
    // a `collect`, a `for`, a `last` — spins.
    let mut it = DirEntries::new(&[0u8; 5]);
    assert!(it.next().unwrap().is_err());
    assert!(it.next().is_none());

    let mut e = Enc::request(0, 0, 4096);
    encode_dirent(&mut e, &DirEntry {
        qid: Qid { ty: qidbits::QTFILE, version: 1, path: 2 }, offset: 1, dtype: 8, name: b"good",
    }).unwrap();
    let f = e.finish().unwrap();
    let mut trunc = f[limits::HDRSZ..].to_vec();
    trunc.extend_from_slice(&[0u8; limits::DIRENT_FIXED_SZ]);
    let got: Vec<NpError> = DirEntries::new(&trunc).filter_map(|r| r.err()).collect();
    assert_eq!(got.len(), 1, "the error repeated");
}
