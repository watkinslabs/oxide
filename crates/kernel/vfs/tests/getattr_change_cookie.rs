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

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use vfs::getattr::{vfs_getattr, vfs_getattr_mask, STATX_BASIC_STATS, STATX_CHANGE_COOKIE};
use vfs::inode::{inode_maybe_inc_iversion, Inode};
use vfs::{FileType, InodeRef, KResult, VfsError, IDENTITY};

/// Inode opting into a change counter (Linux `SB_I_VERSION`), seeded so the
/// real version (`raw >> 1`) is `seed >> 1`.
struct VFile { ver: AtomicU64 }
impl Inode for VFile {
    fn ino(&self) -> vfs::Ino { 9 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn perm(&self) -> Option<u16> { Some(0o644) }
    fn i_version_raw(&self) -> Option<&AtomicU64> { Some(&self.ver) }
}

/// Inode without a counter (the trait default `i_version_raw == None`).
struct Plain;
impl Inode for Plain {
    fn ino(&self) -> vfs::Ino { 10 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn perm(&self) -> Option<u16> { Some(0o644) }
}

/// The plain (request-mask-less) stat path NEVER surfaces the cookie, even for
/// an i_version inode — proving the side-effecting query stays out of stat.
#[test]
fn plain_getattr_never_fills_change_cookie() {
    let inode: InodeRef = Arc::new(VFile { ver: AtomicU64::new(8) });
    let st = vfs_getattr(&inode, &IDENTITY, None);
    assert_eq!(st.result_mask & STATX_CHANGE_COOKIE, 0, "plain stat must not advertise the cookie");
    assert_eq!(st.change_cookie, 0, "plain stat leaves change_cookie zero");
}

/// Requesting the cookie WITHOUT it being set in the mask is a no-op too — the
/// gate is the request mask, mirroring Linux.
#[test]
fn unrequested_mask_leaves_cookie_clear() {
    let inode: InodeRef = Arc::new(VFile { ver: AtomicU64::new(8) });
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
    let vf = Arc::new(VFile { ver: AtomicU64::new(8) });
    let inode: InodeRef = vf.clone();

    // Before any query, a lazy bump is a no-op (nobody queried since last bump).
    assert!(!inode_maybe_inc_iversion(vf.as_ref(), false), "no query yet ⇒ lazy bump skipped");

    let st = vfs_getattr_mask(&inode, &IDENTITY, None, STATX_CHANGE_COOKIE | STATX_BASIC_STATS);
    assert_eq!(st.result_mask & STATX_CHANGE_COOKIE, STATX_CHANGE_COOKIE, "cookie bit set when requested");
    assert_eq!(st.change_cookie, 4, "real version is raw >> 1");
    // The base mask is untouched alongside the added bit.
    assert_eq!(st.result_mask & STATX_BASIC_STATS, STATX_BASIC_STATS, "base stats still reported");

    // The query latched QUERIED, so the next lazy bump now lands.
    assert!(inode_maybe_inc_iversion(vf.as_ref(), false), "query latched ⇒ next lazy bump succeeds");
}

/// Requested but the inode tracks NO counter (`IS_I_VERSION` false): the cookie
/// stays clear — never a fabricated value.
#[test]
fn requested_but_no_counter_stays_clear() {
    let inode: InodeRef = Arc::new(Plain);
    let st = vfs_getattr_mask(&inode, &IDENTITY, None, STATX_CHANGE_COOKIE | STATX_BASIC_STATS);
    assert_eq!(st.result_mask & STATX_CHANGE_COOKIE, 0, "no counter ⇒ no cookie even when requested");
    assert_eq!(st.change_cookie, 0);
}
