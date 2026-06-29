//! `i_version` change-counter (Linux `include/linux/iversion.h`). The lazy
//! NFS/IMA/statx-`STATX_CHANGE_COOKIE` version counter. This proves: the
//! QUERIED-bit layout matches Linux's numeric reps; the lazy bump skips the
//! write until a reader has queried; `inode_inc_iversion` forces a bump; query
//! latches the flag and reports the real (`>> 1`) version; and a fresh inode
//! reports `0`.
//!
//! Migration note (B280b): in the struct-`Inode` model every inode carries an
//! `i_version` store unconditionally (Linux puts the field on the inode; the
//! `SB_I_VERSION` opt-in gates whether the FS *bumps* it, not whether the field
//! exists). The old "counter-less inode no-ops even a forced bump" surface no
//! longer exists; the fresh-inode test now asserts the zero-seed behaviour.

use vfs::inode::{
    inode_inc_iversion, inode_maybe_inc_iversion, inode_peek_iversion_raw, inode_query_iversion,
    inode_set_iversion_raw, InodeBuilder, I_VERSION_INCREMENT, I_VERSION_QUERIED,
    I_VERSION_QUERIED_SHIFT,
};
use vfs::{default_file_ops, default_inode_ops, mk_mode, FileType, InodeRef};

/// Inode seeded with a raw `i_version` word.
fn vfile(seed: u64) -> InodeRef {
    InodeBuilder::new(1, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops())
        .version(seed).build()
}

/// Fresh inode (raw version 0).
fn plain() -> InodeRef {
    InodeBuilder::new(7, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}

/// Linux `include/linux/iversion.h` numeric reps: the flag is bit 0, an
/// increment steps by 2 to clear the flag bit.
#[test]
fn iversion_bit_layout_matches_linux() {
    assert_eq!(I_VERSION_QUERIED_SHIFT, 1);
    assert_eq!(I_VERSION_QUERIED, 0x1);
    assert_eq!(I_VERSION_INCREMENT, 0x2);
}

/// A fresh inode (raw version 0): peek and query both report `0`, and an
/// unqueried non-forced modification skips the bump (Linux's lazy optimization).
#[test]
fn fresh_inode_reports_zero_version() {
    let p = plain();
    assert_eq!(inode_peek_iversion_raw(&p), 0);
    assert!(!inode_maybe_inc_iversion(&p, false), "unqueried ⇒ no bump");
    assert_eq!(inode_query_iversion(&p), 0, "fresh inode real version is 0");
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
