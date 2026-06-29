//! `notify_change` floors the applied timestamps to the backing superblock's
//! `s_time_gran` (Linux `fs/attr.c` `notify_change`, which runs each `ia_*time`
//! through `timestamp_truncate`). A coarse-time backend must never be handed
//! sub-granularity precision it cannot persist. The ctime stamped on every
//! change is floored too; an inode with no `i_sb` (anon/pseudo) keeps full ns.

use std::sync::Arc;
use std::sync::Mutex;

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::superblock::NSEC_PER_SEC;
use vfs::setattr::{notify_change, simple_setattr, Iattr,
    ATTR_ATIME, ATTR_ATIME_SET, ATTR_CTIME, ATTR_MTIME, ATTR_MTIME_SET};
use vfs::{default_file_ops, mk_mode, InodeBuilder, InodeOps};
use vfs::{Cred, FileType, Idmap, InodeRef, KResult, SuperBlock};

struct TFs;
impl FileSystem for TFs {
    fn name(&self) -> &str { "tfs" }
}

fn sb_with_gran(gran: u32) -> Arc<SuperBlock> {
    let sb = SuperBlock::for_backend(Arc::new(TFs), None, 0x55, String::from("tfs"));
    sb.set_time_gran(gran);
    sb
}

/// Backend state (`i_private`): records the `(atime, mtime, ctime)` that the
/// `setattr` apply hands `set_times` — the values `simple_setattr` writes after
/// `notify_change` floors them. Holds the backing `SuperBlock` alive (the inode
/// keeps only a `Weak` to it).
struct TimedData {
    times: Mutex<(Option<u64>, Option<u64>, u64)>,
    _sb: Option<Arc<SuperBlock>>,
}

impl TimedData {
    fn recorded(&self) -> (Option<u64>, Option<u64>, u64) { *self.times.lock().unwrap() }
}

/// `i_op->setattr`: record the floored `set_times` arguments, then apply via the
/// generic `simple_setattr`.
struct TimedOps;
impl InodeOps for TimedOps {
    fn setattr(&self, inode: &Inode, idmap: &Idmap, ia: &Iattr) -> KResult<()> {
        if ia.valid & (ATTR_ATIME | ATTR_MTIME | ATTR_CTIME) != 0 {
            let a = if ia.valid & ATTR_ATIME != 0 { Some(ia.atime_ns) } else { None };
            let m = if ia.valid & ATTR_MTIME != 0 { Some(ia.mtime_ns) } else { None };
            if let Some(d) = inode.private::<TimedData>() {
                *d.times.lock().unwrap() = (a, m, ia.ctime_ns);
            }
        }
        simple_setattr(inode, idmap, ia)
    }
}

/// Regular file (perm 0o644, owner root) bound to `TimedOps`, optionally on the
/// backing `sb`. Returns the inode + the recording state.
fn make_timed(sb: Option<Arc<SuperBlock>>) -> (InodeRef, Arc<TimedData>) {
    let d = Arc::new(TimedData { times: Mutex::new((None, None, 0)), _sb: sb.clone() });
    let mut b = InodeBuilder::new(1, mk_mode(FileType::Regular, 0o644), Arc::new(TimedOps), default_file_ops())
        .owner(0, 0).private(d.clone());
    if let Some(s) = &sb { b = b.sb(Arc::downgrade(s)); }
    (b.build(), d)
}

/// Specific atime/mtime with a 1 s granularity backend: both are floored to the
/// whole second, and the change ctime is floored too.
#[test]
fn second_gran_floors_specific_times() {
    let (inode, raw) = make_timed(Some(sb_with_gran(NSEC_PER_SEC as u32)));
    let mut ia = Iattr {
        valid: ATTR_ATIME | ATTR_MTIME | ATTR_ATIME_SET | ATTR_MTIME_SET | ATTR_CTIME,
        atime_ns: 5 * NSEC_PER_SEC + 999_999_999,
        mtime_ns: 7 * NSEC_PER_SEC + 123,
        ctime_ns: 9 * NSEC_PER_SEC + 42,
        ..Default::default()
    };
    notify_change(&Idmap::identity(), &inode, &mut ia, &Cred::root()).unwrap();
    assert_eq!(raw.recorded(), (Some(5 * NSEC_PER_SEC), Some(7 * NSEC_PER_SEC), 9 * NSEC_PER_SEC));
    // The caller's `ia` is floored in place too (the value the overlay reads).
    assert_eq!(ia.atime_ns, 5 * NSEC_PER_SEC);
    assert_eq!(ia.mtime_ns, 7 * NSEC_PER_SEC);
    assert_eq!(ia.ctime_ns, 9 * NSEC_PER_SEC);
}

/// A 1 ns granularity (the default) is the identity: nothing is perturbed.
#[test]
fn ns_gran_is_identity() {
    let (inode, raw) = make_timed(Some(sb_with_gran(1)));
    let t_a = 3 * NSEC_PER_SEC + 111;
    let t_m = 4 * NSEC_PER_SEC + 222;
    let mut ia = Iattr {
        valid: ATTR_ATIME | ATTR_MTIME | ATTR_ATIME_SET | ATTR_MTIME_SET,
        atime_ns: t_a, mtime_ns: t_m, ctime_ns: 5 * NSEC_PER_SEC + 7,
        ..Default::default()
    };
    notify_change(&Idmap::identity(), &inode, &mut ia, &Cred::root()).unwrap();
    assert_eq!(raw.recorded(), (Some(t_a), Some(t_m), 5 * NSEC_PER_SEC + 7));
}

/// Only the time fields named in `valid` are floored / written; an omitted
/// field (UTIME_OMIT) is left `None`, not flattened to a floored zero.
#[test]
fn omitted_field_not_written() {
    let (inode, raw) = make_timed(Some(sb_with_gran(NSEC_PER_SEC as u32)));
    let mut ia = Iattr {
        valid: ATTR_MTIME | ATTR_MTIME_SET,
        mtime_ns: 8 * NSEC_PER_SEC + 500_000_000,
        ctime_ns: 8 * NSEC_PER_SEC + 500_000_000,
        ..Default::default()
    };
    notify_change(&Idmap::identity(), &inode, &mut ia, &Cred::root()).unwrap();
    let (a, m, c) = raw.recorded();
    assert_eq!(a, None, "atime omitted → left alone");
    assert_eq!(m, Some(8 * NSEC_PER_SEC), "mtime floored to whole second");
    assert_eq!(c, 8 * NSEC_PER_SEC, "ctime floored alongside the mtime change");
    // The untouched atime field is never floored.
    assert_eq!(ia.atime_ns, 0);
}

/// An inode with no backing superblock keeps full-ns precision (granularity is
/// implicitly 1 ns) — the `i_sb` guard skips truncation entirely.
#[test]
fn no_sb_keeps_full_ns() {
    let (inode, raw) = make_timed(None);
    let t_a = 6 * NSEC_PER_SEC + 654_321;
    let t_m = 6 * NSEC_PER_SEC + 123_456;
    let mut ia = Iattr {
        valid: ATTR_ATIME | ATTR_MTIME | ATTR_ATIME_SET | ATTR_MTIME_SET,
        atime_ns: t_a, mtime_ns: t_m, ctime_ns: 6 * NSEC_PER_SEC + 1,
        ..Default::default()
    };
    notify_change(&Idmap::identity(), &inode, &mut ia, &Cred::root()).unwrap();
    assert_eq!(raw.recorded(), (Some(t_a), Some(t_m), 6 * NSEC_PER_SEC + 1));
}
