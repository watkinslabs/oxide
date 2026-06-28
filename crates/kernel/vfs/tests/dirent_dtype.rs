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
