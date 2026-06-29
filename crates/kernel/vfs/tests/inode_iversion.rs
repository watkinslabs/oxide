//! `i_version` change-counter (Linux `include/linux/iversion.h`). The lazy
//! NFS/IMA/statx-`STATX_CHANGE_COOKIE` version counter existed nowhere before:
//! `Inode` had no per-inode version store and the `inode_*_iversion` cmpxchg
//! protocol could not be expressed, so a change-detector could not tell whether
//! an inode's data/metadata moved without re-reading the bytes. This proves:
//! the QUERIED-bit layout matches Linux's numeric reps; the lazy bump skips the
//! write until a reader has queried; `inode_inc_iversion` forces a bump; query
//! latches the flag and reports the real (`>> 1`) version; and a counter-less
//! inode (the trait default) reports `0` with the bump helpers no-oping.

use std::sync::atomic::AtomicU64;

use vfs::inode::{
    inode_inc_iversion, inode_maybe_inc_iversion, inode_peek_iversion_raw, inode_query_iversion,
    inode_set_iversion_raw, Inode, I_VERSION_INCREMENT, I_VERSION_QUERIED, I_VERSION_QUERIED_SHIFT,
};
use vfs::{FileType, InodeRef, KResult, VfsError};

/// Inode that opts into a change counter (Linux `SB_I_VERSION`).
struct VFile { ino: u64, ver: AtomicU64 }
impl Inode for VFile {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn i_version_raw(&self) -> Option<&AtomicU64> { Some(&self.ver) }
}

/// Inode that tracks no version counter (the trait default).
struct Plain { ino: u64 }
impl Inode for Plain {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

fn vfile(seed: u64) -> VFile { VFile { ino: 1, ver: AtomicU64::new(seed) } }

/// Linux `include/linux/iversion.h` numeric reps: the flag is bit 0, an
/// increment steps by 2 to clear the flag bit.
#[test]
fn iversion_bit_layout_matches_linux() {
    assert_eq!(I_VERSION_QUERIED_SHIFT, 1);
    assert_eq!(I_VERSION_QUERIED, 0x1);
    assert_eq!(I_VERSION_INCREMENT, 0x2);
}

/// A counter-less inode (trait default `i_version_raw == None`): query reports
/// `0`, the bump helpers no-op, peek stays `0`.
#[test]
fn no_counter_inode_reports_zero_and_noops() {
    let p = Plain { ino: 7 };
    assert_eq!(inode_peek_iversion_raw(&p), 0);
    assert_eq!(inode_query_iversion(&p), 0);
    assert!(!inode_maybe_inc_iversion(&p, false), "no counter ⇒ no change");
    assert!(!inode_maybe_inc_iversion(&p, true), "force on a counter-less inode still changes nothing");
    inode_inc_iversion(&p); // must not panic
    assert_eq!(inode_peek_iversion_raw(&p), 0);
}

/// Lazy bump: with nobody having queried, a non-forced modification skips the
/// write (Linux's `i_version` optimization). After a query latches the QUERIED
/// flag, the next modification bumps exactly once and re-clears the flag, so a
/// subsequent non-forced modification skips again.
#[test]
fn lazy_bump_only_after_query() {
    let f = vfile(0);
    // Fresh, unqueried: a modification need not be recorded.
    assert!(!inode_maybe_inc_iversion(&f, false), "unqueried ⇒ skip the bump");
    assert_eq!(inode_query_iversion(&f), 0, "real version still 0");

    // Query latched the flag (raw now odd); a modification must now bump.
    assert_eq!(inode_peek_iversion_raw(&f) & I_VERSION_QUERIED, I_VERSION_QUERIED);
    assert!(inode_maybe_inc_iversion(&f, false), "queried ⇒ bump happens");
    assert_eq!(inode_query_iversion(&f), 1, "real version advanced to 1");

    // The bump cleared the flag; the *query* above re-latched it, so bump again.
    assert!(inode_maybe_inc_iversion(&f, false), "re-queried ⇒ bump again");
    assert_eq!(inode_query_iversion(&f), 2, "real version advanced to 2");
}

/// `inode_inc_iversion` forces a bump even with no intervening query (Linux
/// uses it where the change MUST be visible regardless of the lazy flag).
#[test]
fn force_bump_ignores_queried_flag() {
    let f = vfile(0);
    assert_eq!(inode_query_iversion(&f), 0);
    inode_inc_iversion(&f);                  // force, no second query
    assert_eq!(inode_query_iversion(&f), 1);
    inode_inc_iversion(&f);
    inode_inc_iversion(&f);                  // second force WITHOUT a query in between still bumps
    assert_eq!(inode_query_iversion(&f), 3);
}

/// `inode_set_iversion_raw` seeds the stored word verbatim (a FS loading an
/// on-disk `i_version`); query reports the seeded real version and latches.
#[test]
fn set_raw_seeds_then_query_reports_real_version() {
    let f = vfile(0);
    // Seed real version 42 with the flag clear: raw = 42 << 1 = 84.
    inode_set_iversion_raw(&f, 42 << I_VERSION_QUERIED_SHIFT);
    assert_eq!(inode_peek_iversion_raw(&f), 84);
    assert_eq!(inode_query_iversion(&f), 42, "query reports seeded real version");
    // Query latched the flag; one bump advances the real version to 43.
    assert!(inode_maybe_inc_iversion(&f, false));
    assert_eq!(inode_query_iversion(&f), 43);
}
