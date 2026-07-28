//! inode-D25: `i_op->update_time` + `generic_update_time` timestamp-update
//! policy. The op selects WHICH of atime/mtime/ctime a touch writes to `now`
//! (the `S_ATIME`/`S_MTIME`/`S_CTIME` flags) and lazily bumps `i_version` on
//! `S_VERSION`. The default trait body is `generic_update_time`, reached via the
//! `Inode::update_time` delegator.
//!
//! Fails-before: there was no `update_time` op at all (grep update_time = empty),
//! so a touch had to open-code the time write at every call site with no shared
//! policy — and a single-field touch could not avoid clobbering the others.

use vfs::{FileType, InodeBuilder, Timespec64, default_file_ops, default_inode_ops, mk_mode,
          generic_update_time, S_ATIME, S_MTIME, S_CTIME, S_VERSION};

/// Whole-second helper — these tests care about which FIELD moves, not scale.
fn ts(sec: i64) -> Timespec64 { Timespec64::from_secs(sec) }

fn inode(a: i64, m: i64, c: i64, version: u64) -> vfs::InodeRef {
    InodeBuilder::new(1, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops())
        .times(ts(a), ts(m), ts(c)).version(version).build()
}

// S_ATIME alone updates atime to `now` and leaves mtime/ctime untouched.
#[test]
fn s_atime_updates_only_atime() {
    let i = inode(100, 200, 300, 0);
    i.update_time(ts(999), S_ATIME).expect("update_time");
    assert_eq!(i.atime(), Some(ts(999)));
    assert_eq!(i.mtime(), Some(ts(200)), "mtime untouched");
    assert_eq!(i.ctime(), Some(ts(300)), "ctime untouched without S_CTIME");
}

// S_MTIME | S_CTIME writes both to `now`, atime untouched.
#[test]
fn s_mtime_ctime_updates_both() {
    let i = inode(100, 200, 300, 0);
    i.update_time(ts(999), S_MTIME | S_CTIME).expect("update_time");
    assert_eq!(i.atime(), Some(ts(100)), "atime untouched");
    assert_eq!(i.mtime(), Some(ts(999)));
    assert_eq!(i.ctime(), Some(ts(999)));
}

// No time flag => nothing changes (and still Ok).
#[test]
fn no_flags_is_noop() {
    let i = inode(100, 200, 300, 0);
    i.update_time(ts(999), 0).expect("update_time");
    assert_eq!((i.atime(), i.mtime(), i.ctime()), (Some(ts(100)), Some(ts(200)), Some(ts(300))));
}

// S_VERSION lazily bumps i_version, but only after the QUERIED flag is latched
// (Linux `inode_maybe_inc_iversion(force=false)`): a never-queried version is
// not bumped; once queried, the next S_VERSION touch advances it.
#[test]
fn s_version_lazy_bump() {
    let i = inode(0, 0, 0, 0);
    let before = vfs::inode::inode_peek_iversion_raw(&i);
    generic_update_time(&i, ts(1), S_VERSION).expect("update_time");
    assert_eq!(vfs::inode::inode_peek_iversion_raw(&i), before, "no bump until queried");
    let _ = vfs::inode::inode_query_iversion(&i); // latch QUERIED
    generic_update_time(&i, ts(2), S_VERSION).expect("update_time");
    assert!(vfs::inode::inode_peek_iversion_raw(&i) > before, "bumped after query");
}

/// F767: `update_time` carries a PRE-1970 stamp into the inode unchanged, and
/// an untouched field keeps its own (also pre-1970) value.
#[test]
fn pre_epoch_now_is_stored_verbatim() {
    let i = inode(-100, -200, -300, 0);
    let now = Timespec64::new(-2_000_000_000, 123); // 1906-08-16
    i.update_time(now, S_MTIME | S_CTIME).expect("update_time");
    assert_eq!(i.atime(), Some(ts(-100)), "atime untouched, still negative");
    assert_eq!(i.mtime(), Some(now));
    assert_eq!(i.ctime(), Some(now));
}
