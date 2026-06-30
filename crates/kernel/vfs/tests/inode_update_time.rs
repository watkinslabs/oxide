//! inode-D25: `i_op->update_time` + `generic_update_time` timestamp-update
//! policy. The op selects WHICH of atime/mtime/ctime a touch writes to `now`
//! (the `S_ATIME`/`S_MTIME`/`S_CTIME` flags) and lazily bumps `i_version` on
//! `S_VERSION`. The default trait body is `generic_update_time`, reached via the
//! `Inode::update_time` delegator.
//!
//! Fails-before: there was no `update_time` op at all (grep update_time = empty),
//! so a touch had to open-code the time write at every call site with no shared
//! policy — and a single-field touch could not avoid clobbering the others.

use vfs::{FileType, InodeBuilder, default_file_ops, default_inode_ops, mk_mode,
          generic_update_time, S_ATIME, S_MTIME, S_CTIME, S_VERSION};

fn inode(a: u64, m: u64, c: u64, version: u64) -> vfs::InodeRef {
    InodeBuilder::new(1, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops())
        .times(a, m, c).version(version).build()
}

// S_ATIME alone updates atime to `now` and leaves mtime/ctime untouched.
#[test]
fn s_atime_updates_only_atime() {
    let i = inode(100, 200, 300, 0);
    i.update_time(999, S_ATIME).expect("update_time");
    assert_eq!(i.atime(), Some(999));
    assert_eq!(i.mtime(), Some(200), "mtime untouched");
    assert_eq!(i.ctime(), Some(300), "ctime untouched without S_CTIME");
}

// S_MTIME | S_CTIME writes both to `now`, atime untouched.
#[test]
fn s_mtime_ctime_updates_both() {
    let i = inode(100, 200, 300, 0);
    i.update_time(999, S_MTIME | S_CTIME).expect("update_time");
    assert_eq!(i.atime(), Some(100), "atime untouched");
    assert_eq!(i.mtime(), Some(999));
    assert_eq!(i.ctime(), Some(999));
}

// No time flag => nothing changes (and still Ok).
#[test]
fn no_flags_is_noop() {
    let i = inode(100, 200, 300, 0);
    i.update_time(999, 0).expect("update_time");
    assert_eq!((i.atime(), i.mtime(), i.ctime()), (Some(100), Some(200), Some(300)));
}

// S_VERSION lazily bumps i_version, but only after the QUERIED flag is latched
// (Linux `inode_maybe_inc_iversion(force=false)`): a never-queried version is
// not bumped; once queried, the next S_VERSION touch advances it.
#[test]
fn s_version_lazy_bump() {
    let i = inode(0, 0, 0, 0);
    let before = vfs::inode::inode_peek_iversion_raw(&i);
    generic_update_time(&i, 1, S_VERSION).expect("update_time");
    assert_eq!(vfs::inode::inode_peek_iversion_raw(&i), before, "no bump until queried");
    let _ = vfs::inode::inode_query_iversion(&i); // latch QUERIED
    generic_update_time(&i, 2, S_VERSION).expect("update_time");
    assert!(vfs::inode::inode_peek_iversion_raw(&i) > before, "bumped after query");
}
