//! getdents dirent emitter (`19§4` / `15§4`): the `d_type` byte each
//! `linux_dirent*` record carries must be the Linux `DT_*` tag derived from the
//! inode's `S_IFMT` bits via `IFTODT(mode) = (mode & S_IFMT) >> 12`, and the
//! record framing (`d_ino`, `d_off` cursor, 8-byte-aligned `d_reclen`, `d_type`
//! placement) must match the fixed kernel ABI byte-for-byte. Driven over the
//! pure packer helpers — no QEMU, no global state, so no serial guard.
//!
//! Pins the regression the syscall shim used to risk: a hand-rolled
//! `FileType -> d_type` match with bare literals (`DT_REG == 8`) that could
//! drift from `stat`'s mode word. `dtype_from_file_type` now reuses
//! `FileType::to_ifmt` as the single source of truth.

use vfs::dirent::{
    dtype_from_file_type, DT_BLK, DT_CHR, DT_DIR, DT_FIFO, DT_LNK, DT_REG, DT_SOCK, DT_UNKNOWN,
};
use vfs::{dirent64_pack, dirent64_reclen, dirent_pack, dirent_reclen, FileType};

/// Linux `include/linux/fs_types.h` numeric `DT_*` values — frozen by the ABI.
#[test]
fn dt_constants_match_linux_uapi() {
    assert_eq!(DT_UNKNOWN, 0);
    assert_eq!(DT_FIFO, 1);
    assert_eq!(DT_CHR, 2);
    assert_eq!(DT_DIR, 4);
    assert_eq!(DT_BLK, 6);
    assert_eq!(DT_REG, 8);
    assert_eq!(DT_LNK, 10);
    assert_eq!(DT_SOCK, 12);
}

/// Every `FileType` maps to the `DT_*` tag Linux `readdir(3)` expects.
#[test]
fn dtype_derivation_covers_every_file_type() {
    assert_eq!(dtype_from_file_type(FileType::Regular), DT_REG);
    assert_eq!(dtype_from_file_type(FileType::Directory), DT_DIR);
    assert_eq!(dtype_from_file_type(FileType::Symlink), DT_LNK);
    assert_eq!(dtype_from_file_type(FileType::CharDev), DT_CHR);
    assert_eq!(dtype_from_file_type(FileType::BlockDev), DT_BLK);
    assert_eq!(dtype_from_file_type(FileType::Fifo), DT_FIFO);
    assert_eq!(dtype_from_file_type(FileType::Socket), DT_SOCK);
}

/// `DT_x == (S_IFx >> 12)` — the derivation never diverges from the mode word
/// `stat` reports (`FileType::to_ifmt`), so `ls -F` and `stat` always agree.
#[test]
fn dtype_equals_iftodt_of_mode() {
    for ft in [
        FileType::Regular,
        FileType::Directory,
        FileType::Symlink,
        FileType::CharDev,
        FileType::BlockDev,
        FileType::Fifo,
        FileType::Socket,
    ] {
        assert_eq!(dtype_from_file_type(ft) as u16, ft.to_ifmt() >> 12);
    }
}

/// `linux_dirent64`: `d_ino`@0, `d_off`@8 (next-entry cursor), `d_reclen`@16
/// (8-aligned u16), `d_type`@18, NUL-terminated name@19. Parse the packed
/// bytes back and assert every field.
#[test]
fn dirent64_field_layout_round_trips() {
    let name = b"passwd";
    let reclen = dirent64_reclen(name.len());
    assert_eq!(reclen % 8, 0, "d_reclen must be 8-byte aligned");

    let mut buf = [0u8; 64];
    let n = dirent64_pack(&mut buf, 0x1234, 0x99, DT_REG, name).expect("fits");
    assert_eq!(n, reclen);

    assert_eq!(u64::from_le_bytes(buf[0..8].try_into().unwrap()), 0x1234);
    assert_eq!(u64::from_le_bytes(buf[8..16].try_into().unwrap()), 0x99);
    assert_eq!(u16::from_le_bytes(buf[16..18].try_into().unwrap()) as usize, reclen);
    assert_eq!(buf[18], DT_REG);
    assert_eq!(&buf[19..19 + name.len()], name);
    assert_eq!(buf[19 + name.len()], 0, "name must be NUL-terminated");
}

/// Legacy `linux_dirent` (NR 78): `d_type` lives in the record's LAST byte
/// (`d_reclen - 1`), not at a fixed offset. glibc reads it there.
#[test]
fn legacy_dirent_d_type_is_trailing_byte() {
    let name = b"dev";
    let reclen = dirent_reclen(name.len());
    assert_eq!(reclen % 8, 0, "d_reclen must be 8-byte aligned");

    let mut buf = [0u8; 64];
    let n = dirent_pack(&mut buf, 0x42, 0x7, DT_DIR, name).expect("fits");
    assert_eq!(n, reclen);

    assert_eq!(u64::from_le_bytes(buf[0..8].try_into().unwrap()), 0x42);
    assert_eq!(u64::from_le_bytes(buf[8..16].try_into().unwrap()), 0x7);
    assert_eq!(u16::from_le_bytes(buf[16..18].try_into().unwrap()) as usize, reclen);
    assert_eq!(&buf[18..18 + name.len()], name);
    assert_eq!(buf[18 + name.len()], 0, "name must be NUL-terminated");
    assert_eq!(buf[reclen - 1], DT_DIR, "d_type at last byte");
}

/// reclen rounds the raw record up to the next multiple of 8 across name
/// lengths — the kernel `ALIGN(.., sizeof(long))` contract.
#[test]
fn reclen_alignment_across_name_lengths() {
    for len in 0..=40usize {
        assert_eq!(dirent64_reclen(len) % 8, 0);
        assert_eq!(dirent_reclen(len) % 8, 0);
        // strictly larger than the raw header+name to leave room for the
        // NUL (and, legacy, the trailing d_type byte).
        assert!(dirent64_reclen(len) >= 19 + len + 1);
        assert!(dirent_reclen(len) >= 18 + len + 2);
    }
}

/// Packing into a buffer too small for the record returns `None` (the emitter
/// stops rather than writing a torn record — the `filldir` overflow contract).
#[test]
fn pack_rejects_undersized_buffer() {
    let name = b"toolongforthis";
    let mut small = [0u8; 8];
    assert!(dirent64_pack(&mut small, 1, 1, DT_REG, name).is_none());
    assert!(dirent_pack(&mut small, 1, 1, DT_REG, name).is_none());
}

// ---------------------------------------------------------------------------
// readdir cursor stability (telldir/seekdir): the `d_off` cookie packed with
// each record is an OPAQUE position (Linux `ctx->pos`), not a byte offset into
// the user buffer. A subsequent getdents resumes from the cookie of the LAST
// record that fit, so a multi-call paginated read returns every entry exactly
// once — no duplicates, no skips — across the buffer-overflow boundary.
// ---------------------------------------------------------------------------

/// One directory child, as `i_op->iterate`/`dir_emit` sees it.
#[derive(Clone)]
struct Ent { ino: u64, name: &'static [u8], ft: FileType }

/// A parsed-back `linux_dirent64` record (the userspace `readdir(3)` view).
struct Rec { ino: u64, off: u64, name: Vec<u8> }

/// Pack one getdents64 page exactly as `sys_getdents64` does: walk `dir` from
/// the opaque ordinal cursor `start`, pack each record while it fits `cap`
/// bytes, and return `(bytes_written, resume_cursor)`. `resume_cursor` is the
/// `d_off` cookie of the last record that fit — the position the NEXT call
/// resumes *after*. Mirrors the index-based cookie tmpfs/ramfs assign
/// (`cookie = idx + 1`, `readdir(off)` does `skip(off)`).
fn getdents_page(dir: &[Ent], start: u64, cap: usize, buf: &mut [u8]) -> (usize, u64) {
    let mut written = 0usize;
    let mut resume = start;
    for (i, e) in dir.iter().enumerate().skip(start as usize) {
        let cookie = (i + 1) as u64;            // opaque ordinal, NOT a byte offset
        let reclen = dirent64_reclen(e.name.len());
        if written + reclen > cap { break; }     // filldir overflow → stop, don't tear
        let dt = dtype_from_file_type(e.ft);
        dirent64_pack(&mut buf[written..], e.ino, cookie, dt, e.name).expect("sized to reclen");
        written += reclen;
        resume = cookie;                         // advance cursor only on a record that fit
    }
    (written, resume)
}

/// Parse a packed getdents64 buffer back into records (the glibc reader walk:
/// step by `d_reclen`, read `d_ino`@0 / `d_off`@8 / name@19..NUL).
fn parse_page(buf: &[u8]) -> Vec<Rec> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p < buf.len() {
        let reclen = u16::from_le_bytes(buf[p + 16..p + 18].try_into().unwrap()) as usize;
        if reclen == 0 { break; }
        let ino = u64::from_le_bytes(buf[p..p + 8].try_into().unwrap());
        let off = u64::from_le_bytes(buf[p + 8..p + 16].try_into().unwrap());
        let nstart = p + 19;
        let nlen = buf[nstart..p + reclen].iter().position(|&b| b == 0).unwrap();
        out.push(Rec { ino, off, name: buf[nstart..nstart + nlen].to_vec() });
        p += reclen;
    }
    out
}

fn fixture() -> [Ent; 5] {
    [
        Ent { ino: 11, name: b"alpha",   ft: FileType::Regular   },
        Ent { ino: 12, name: b"bravo",   ft: FileType::Directory },
        Ent { ino: 13, name: b"charlie", ft: FileType::Symlink   },
        Ent { ino: 14, name: b"delta",   ft: FileType::Regular   },
        Ent { ino: 15, name: b"echo",    ft: FileType::CharDev   },
    ]
}

/// Two-call paginated read: a first page sized for exactly two records, then a
/// second page from the returned cursor, must reconstruct the directory exactly
/// once — every entry present, in order, none duplicated, none skipped.
#[test]
fn paginated_readdir_resumes_without_dup_or_skip() {
    let dir = fixture();
    let cap1 = dirent64_reclen(dir[0].name.len()) + dirent64_reclen(dir[1].name.len());

    let mut buf = [0u8; 512];
    let (n1, cur1) = getdents_page(&dir, 0, cap1, &mut buf);
    let page1 = parse_page(&buf[..n1]);
    assert_eq!(page1.len(), 2, "first page holds exactly two records");
    // Resume cursor is the LAST record's d_off — an opaque ordinal (2 entries
    // consumed), NOT the byte length of what was written.
    assert_eq!(cur1, page1.last().unwrap().off, "cursor = last record's d_off");
    assert_eq!(cur1, 2, "ordinal position, two entries consumed");
    assert_ne!(cur1 as usize, n1, "cursor is a position, not a buffer byte offset");

    let (n2, cur2) = getdents_page(&dir, cur1, 512, &mut buf);
    let page2 = parse_page(&buf[..n2]);
    assert_eq!(page2.len(), 3, "remaining three records on the second call");
    assert_eq!(cur2, 5, "cursor at end-of-directory = entry count");

    // Concatenation equals the directory, in order, exactly once.
    let got: Vec<Vec<u8>> = page1.iter().chain(&page2).map(|r| r.name.clone()).collect();
    let want: Vec<Vec<u8>> = dir.iter().map(|e| e.name.to_vec()).collect();
    assert_eq!(got, want, "no duplicate, no skip, order preserved");

    // d_ino round-trips per entry (ls -i / find -inum), no entry seen twice.
    let inos: Vec<u64> = page1.iter().chain(&page2).map(|r| r.ino).collect();
    let mut sorted = inos.clone(); sorted.sort_unstable(); sorted.dedup();
    assert_eq!(sorted.len(), inos.len(), "every inode emitted exactly once");
    assert_eq!(inos, vec![11, 12, 13, 14, 15]);
}

/// Each record's `d_off` is the ordinal of the next resume point (1,2,3,…),
/// strictly increasing and independent of record byte sizes — seekdir(cookie)
/// lands exactly after that entry regardless of name length / buffer layout.
#[test]
fn d_off_cookies_are_opaque_increasing_ordinals() {
    let dir = fixture();
    let mut buf = [0u8; 512];
    let (n, end) = getdents_page(&dir, 0, 512, &mut buf);
    let recs = parse_page(&buf[..n]);
    assert_eq!(recs.len(), 5);
    let offs: Vec<u64> = recs.iter().map(|r| r.off).collect();
    assert_eq!(offs, vec![1, 2, 3, 4, 5], "cookies are positions, not byte offsets");
    assert_eq!(end, 5);
    // Strictly increasing — a monotone cursor telldir can store and seekdir to.
    assert!(offs.windows(2).all(|w| w[0] < w[1]));
}

/// seekdir to an arbitrary mid-directory cookie yields exactly the suffix after
/// it — resuming from cookie K returns entries K..end with no replay of K's
/// predecessors and no skip of K+1.
#[test]
fn seekdir_to_mid_cookie_yields_exact_suffix() {
    let dir = fixture();
    let mut buf = [0u8; 512];
    // Resume from cookie 3 → entries at ordinals 3,4 (i.e. delta, echo).
    let (n, end) = getdents_page(&dir, 3, 512, &mut buf);
    let recs = parse_page(&buf[..n]);
    let names: Vec<Vec<u8>> = recs.iter().map(|r| r.name.clone()).collect();
    assert_eq!(names, vec![b"delta".to_vec(), b"echo".to_vec()]);
    assert_eq!(end, 5);
}

/// A buffer too small for even the first record packs nothing and leaves the
/// cursor untouched — the caller (getdents) reports EINVAL rather than treating
/// the empty pack as end-of-directory, so the entry is re-attempted next call.
#[test]
fn first_record_overflow_does_not_advance_cursor() {
    let dir = fixture();
    let too_small = dirent64_reclen(dir[0].name.len()) - 8; // below one record
    let mut buf = [0u8; 512];
    let (n, cur) = getdents_page(&dir, 0, too_small, &mut buf);
    assert_eq!(n, 0, "no record fit");
    assert_eq!(cur, 0, "cursor not advanced — entry retried, never skipped");
}
