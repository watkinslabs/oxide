//! `STATX_CHANGE_COOKIE` wiring (Linux `fs/stat.c` `vfs_getattr_nosec` +
//! `generic_fillattr`). The i_version change counter (B210) existed but no
//! stat path surfaced it: `generic_fillattr` never set `stx_change_attr`, so
//! statx callers could not read the cookie an NFS/IMA change-detector compares.
//!
//! Linux contract pinned here:
//!   * the unconditional `generic_fillattr`/`vfs_getattr` NEVER fills the cookie
//!     (querying it latches the inode QUERIED flag — a plain stat must not pay
//!     that side effect);
//!   * `vfs_getattr_mask` fills `change_cookie` and sets `STATX_CHANGE_COOKIE`
//!     in `result_mask` only when the bit is REQUESTED *and* the inode carries
//!     an `i_version` (`IS_I_VERSION`);
//!   * the value is the real version (`stored >> 1`), and the query latches the
//!     QUERIED flag so the next modification is guaranteed to bump.
//!
//! Concrete-inode-model note (B280b): every `struct Inode` now carries an
//! `i_version` word, so `i_version_raw()` is always `Some` — the old "no
//! counter" inode that left the cookie clear no longer exists. The seed is set
//! via `InodeBuilder::version` instead of an overridden `i_version_raw`.

use vfs::getattr::{vfs_getattr, vfs_getattr_mask, STATX_BASIC_STATS, STATX_CHANGE_COOKIE};
use vfs::inode::inode_maybe_inc_iversion;
use vfs::{FileType, InodeBuilder, InodeRef, IDENTITY,
          default_file_ops, default_inode_ops, mk_mode};

/// Inode with a change counter seeded so the real version (`raw >> 1`) is
/// `seed >> 1`.
fn vfile(seed: u64) -> InodeRef {
    InodeBuilder::new(9, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops())
        .version(seed).build()
}

/// The plain (request-mask-less) stat path NEVER surfaces the cookie, even for
/// an i_version inode — proving the side-effecting query stays out of stat.
#[test]
fn plain_getattr_never_fills_change_cookie() {
    let inode: InodeRef = vfile(8);
    let st = vfs_getattr(&inode, &IDENTITY, None);
    assert_eq!(st.result_mask & STATX_CHANGE_COOKIE, 0, "plain stat must not advertise the cookie");
    assert_eq!(st.change_cookie, 0, "plain stat leaves change_cookie zero");
}

/// Requesting the cookie WITHOUT it being set in the mask is a no-op too — the
/// gate is the request mask, mirroring Linux.
#[test]
fn unrequested_mask_leaves_cookie_clear() {
    let inode: InodeRef = vfile(8);
    // Request only the basic stats, not the change cookie.
    let st = vfs_getattr_mask(&inode, &IDENTITY, None, STATX_BASIC_STATS);
    assert_eq!(st.result_mask & STATX_CHANGE_COOKIE, 0, "not requested ⇒ not filled");
    assert_eq!(st.change_cookie, 0);
}

/// Requested + i_version present: the cookie is filled with the real version
/// (`raw >> 1`), the result bit is set, and the query LATCHED the QUERIED flag
/// so a subsequent lazy bump now succeeds (was a no-op before the query).
#[test]
fn requested_fills_real_version_and_latches() {
    // raw 8 → QUERIED clear, real version 8>>1 = 4.
    let inode: InodeRef = vfile(8);

    // Before any query, a lazy bump is a no-op (nobody queried since last bump).
    assert!(!inode_maybe_inc_iversion(&inode, false), "no query yet ⇒ lazy bump skipped");

    let st = vfs_getattr_mask(&inode, &IDENTITY, None, STATX_CHANGE_COOKIE | STATX_BASIC_STATS);
    assert_eq!(st.result_mask & STATX_CHANGE_COOKIE, STATX_CHANGE_COOKIE, "cookie bit set when requested");
    assert_eq!(st.change_cookie, 4, "real version is raw >> 1");
    // The base mask is untouched alongside the added bit.
    assert_eq!(st.result_mask & STATX_BASIC_STATS, STATX_BASIC_STATS, "base stats still reported");

    // The query latched QUERIED, so the next lazy bump now lands.
    assert!(inode_maybe_inc_iversion(&inode, false), "query latched ⇒ next lazy bump succeeds");
}

/// Requested on a concrete inode (which ALWAYS carries an i_version now): the
/// cookie is filled with the real version. The old "no counter ⇒ clear" case no
/// longer exists — every `struct Inode` has the change counter.
#[test]
fn requested_fills_cookie_for_concrete_inode() {
    let inode: InodeRef = vfile(6); // real version 6>>1 = 3
    let st = vfs_getattr_mask(&inode, &IDENTITY, None, STATX_CHANGE_COOKIE | STATX_BASIC_STATS);
    assert_eq!(st.result_mask & STATX_CHANGE_COOKIE, STATX_CHANGE_COOKIE,
               "concrete inode always carries i_version ⇒ cookie surfaced when requested");
    assert_eq!(st.change_cookie, 3, "real version is raw >> 1");
}
