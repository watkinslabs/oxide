//! D35: `Fmode` carries the previously-missing `file->f_mode` state bits
//! `FMODE_OPENED` / `FMODE_CREATED` / `FMODE_NONOTIFY`. Pin their numeric
//! values to Linux `include/linux/fs.h` and confirm they are independent of
//! the access-capability bits already present (READ/WRITE/PATH).

use vfs::Fmode;

/// Values match Linux `fs.h` exactly (`1 << 19/20/26`).
#[test]
fn values_match_linux() {
    assert_eq!(Fmode::OPENED.bits(),   0x0008_0000, "FMODE_OPENED  = 1<<19");
    assert_eq!(Fmode::CREATED.bits(),  0x0010_0000, "FMODE_CREATED = 1<<20");
    assert_eq!(Fmode::NONOTIFY.bits(), 0x0400_0000, "FMODE_NONOTIFY = 1<<26");
}

/// The new state bits do not overlap each other or the access bits, so they
/// compose independently into an `f_mode` word.
#[test]
fn bits_are_disjoint() {
    let access = Fmode::READ | Fmode::WRITE | Fmode::PATH | Fmode::LSEEK
        | Fmode::PREAD | Fmode::PWRITE | Fmode::EXEC;
    for bit in [Fmode::OPENED, Fmode::CREATED, Fmode::NONOTIFY] {
        assert!(!access.intersects(bit), "{:?} disjoint from access bits", bit);
    }
    assert!(!Fmode::OPENED.intersects(Fmode::CREATED));
    assert!(!Fmode::OPENED.intersects(Fmode::NONOTIFY));
    assert!(!Fmode::CREATED.intersects(Fmode::NONOTIFY));
}

/// A composed `f_mode` (e.g. a freshly-created, opened, writable file) reports
/// each bit independently — `contains` round-trips.
#[test]
fn compose_and_query() {
    let m = Fmode::READ | Fmode::WRITE | Fmode::OPENED | Fmode::CREATED;
    assert!(m.contains(Fmode::OPENED));
    assert!(m.contains(Fmode::CREATED));
    assert!(!m.contains(Fmode::NONOTIFY));
    assert!(m.contains(Fmode::WRITE));
}
