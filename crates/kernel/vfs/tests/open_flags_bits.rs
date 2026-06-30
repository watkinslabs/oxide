//! D22: the typed `OpenFlags` set carries the previously-missing `open(2)`
//! status / open-time bits (`O_SYNC`/`O_DSYNC`/`O_DIRECT`/`O_NOATIME`/
//! `O_NOCTTY`/`O_LARGEFILE`/`O_PATH`/`O_TMPFILE`). Pre-fix they lived only as
//! ad-hoc syscall-layer consts and `from_bits_truncate` SILENTLY STRIPPED them
//! off the open word. These tests pin the numeric values to the x86_64 /
//! asm-generic uapi (`include/uapi/asm-generic/fcntl.h`) — the single source of
//! truth the whole vfs crate now shares — and assert the bits survive a
//! `from_bits_truncate` round-trip.

use vfs::OpenFlags;

/// Each new bit's numeric value matches the Linux asm-generic uapi exactly.
#[test]
fn values_match_uapi() {
    assert_eq!(OpenFlags::O_NOCTTY.bits(),    0o400,      "O_NOCTTY");
    assert_eq!(OpenFlags::O_DSYNC.bits(),     0o10000,    "O_DSYNC");
    assert_eq!(OpenFlags::O_DIRECT.bits(),    0o40000,    "O_DIRECT");
    assert_eq!(OpenFlags::O_LARGEFILE.bits(), 0o100000,   "O_LARGEFILE");
    assert_eq!(OpenFlags::O_NOATIME.bits(),   0o1000000,  "O_NOATIME");
    assert_eq!(OpenFlags::O_SYNC.bits(),      0o4010000,  "O_SYNC");
    assert_eq!(OpenFlags::O_PATH.bits(),      0o10000000, "O_PATH");
    assert_eq!(OpenFlags::O_TMPFILE.bits(),   0o20200000, "O_TMPFILE");
}

/// `O_SYNC` is `__O_SYNC | O_DSYNC` — it CONTAINS the `O_DSYNC` bit (Linux
/// `O_SYNC` definition), so a synchronised-I/O file-integrity open implies the
/// data-integrity bit too.
#[test]
fn sync_contains_dsync() {
    assert!(OpenFlags::O_SYNC.contains(OpenFlags::O_DSYNC));
}

/// `O_TMPFILE` is `__O_TMPFILE | O_DIRECTORY` — it CONTAINS `O_DIRECTORY`
/// (Linux requires the dir operand), matching the uapi composition.
#[test]
fn tmpfile_contains_directory() {
    assert!(OpenFlags::O_TMPFILE.contains(OpenFlags::O_DIRECTORY));
}

/// The regression that motivated D22: `from_bits_truncate` no longer DROPS
/// these bits. Build a raw open word with every new bit set and confirm the
/// truncating constructor preserves them all.
#[test]
fn from_bits_truncate_preserves_new_bits() {
    let raw = OpenFlags::O_RDWR.bits()
        | OpenFlags::O_NOCTTY.bits()
        | OpenFlags::O_DSYNC.bits()
        | OpenFlags::O_DIRECT.bits()
        | OpenFlags::O_LARGEFILE.bits()
        | OpenFlags::O_NOATIME.bits()
        | OpenFlags::O_SYNC.bits()
        | OpenFlags::O_PATH.bits()
        | OpenFlags::O_TMPFILE.bits();
    let f = OpenFlags::from_bits_truncate(raw);
    assert_eq!(f.bits(), raw, "no declared bit is truncated away");
    for bit in [OpenFlags::O_NOCTTY, OpenFlags::O_DSYNC, OpenFlags::O_DIRECT,
                OpenFlags::O_LARGEFILE, OpenFlags::O_NOATIME, OpenFlags::O_SYNC,
                OpenFlags::O_PATH, OpenFlags::O_TMPFILE] {
        assert!(f.contains(bit), "bit {:?} preserved", bit);
    }
}
