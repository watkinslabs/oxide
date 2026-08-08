//! `notify_change` floors the applied timestamps to the backing superblock's
//! `s_time_gran` (`notify_change` runs each `ia_*time`
//! through `timestamp_truncate`). A coarse-time backend must never be handed
//! sub-granularity precision it cannot persist. The ctime stamped on every
//! change is floored too; an inode with no `i_sb` (anon/pseudo) keeps full ns.

use std::sync::Arc;
use std::sync::Mutex;

mod common;

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::timespec::NSEC_PER_SEC;
use vfs::setattr::{notify_change, simple_setattr, Iattr,
    ATTR_ATIME, ATTR_ATIME_SET, ATTR_CTIME, ATTR_MTIME, ATTR_MTIME_SET};
use vfs::{default_file_ops, mk_mode, InodeBuilder, InodeOps};
use vfs::{Cred, FileType, Idmap, InodeRef, KResult, SuperBlock, Timespec64};

struct TFs;
impl FileSystem for TFs {
    fn name(&self) -> &str { "tfs" }
}

fn sb_with_gran(gran: u32) -> Arc<SuperBlock> {
    let sb = common::realize_sb(Arc::new(TFs), None, 0x55, String::from("tfs"));
    sb.set_time_gran(gran);
    sb
}

/// Backend state (`i_private`): records the `(atime, mtime, ctime)` that the
/// `setattr` apply hands `set_times` — the values `simple_setattr` writes after
/// `notify_change` floors them. Holds the backing `SuperBlock` alive (the inode
/// keeps only a `Weak` to it).
struct TimedData {
    times: Mutex<(Option<Timespec64>, Option<Timespec64>, Timespec64)>,
    _sb: Option<Arc<SuperBlock>>,
}

impl TimedData {
    fn recorded(&self) -> (Option<Timespec64>, Option<Timespec64>, Timespec64) { *self.times.lock().unwrap() }
}

/// `i_op->setattr`: record the floored `set_times` arguments, then apply via the
/// generic `simple_setattr`.
struct TimedOps;
impl InodeOps for TimedOps {
    fn setattr(&self, inode: &Inode, idmap: &Idmap, ia: &Iattr) -> KResult<()> {
        if ia.valid & (ATTR_ATIME | ATTR_MTIME | ATTR_CTIME) != 0 {
            let a = if ia.valid & ATTR_ATIME != 0 { Some(ia.atime) } else { None };
            let m = if ia.valid & ATTR_MTIME != 0 { Some(ia.mtime) } else { None };
            if let Some(d) = inode.private::<TimedData>() {
                *d.times.lock().unwrap() = (a, m, ia.ctime);
            }
        }
        simple_setattr(inode, idmap, ia)
    }
}

/// Regular file (perm 0o644, owner root) bound to `TimedOps`, optionally on the
/// backing `sb`. Returns the inode + the recording state.
fn make_timed(sb: Option<Arc<SuperBlock>>) -> (InodeRef, Arc<TimedData>) {
    let d = Arc::new(TimedData { times: Mutex::new((None, None, Timespec64::ZERO)), _sb: sb.clone() });
    let mut b = InodeBuilder::new(1, mk_mode(FileType::Regular, 0o644), Arc::new(TimedOps), default_file_ops())
        .owner(0, 0).private(d.clone());
    if let Some(s) = &sb { b = b.sb(Arc::downgrade(s)); }
    (b.build(), d)
}

/// Specific atime/mtime with a 1 s granularity backend: both are floored to the
/// whole second, and the change ctime is floored too.
#[test]
fn second_gran_floors_specific_times() {
    let (inode, raw) = make_timed(Some(sb_with_gran(NSEC_PER_SEC)));
    let mut ia = Iattr {
        valid: ATTR_ATIME | ATTR_MTIME | ATTR_ATIME_SET | ATTR_MTIME_SET | ATTR_CTIME,
        atime: Timespec64::new(5, 999_999_999),
        mtime: Timespec64::new(7, 123),
        ctime: Timespec64::new(9, 42),
        ..Default::default()
    };
    notify_change(&Idmap::identity(), &inode, &mut ia, &Cred::root()).unwrap();
    assert_eq!(raw.recorded(), (Some(Timespec64::from_secs(5)), Some(Timespec64::from_secs(7)), Timespec64::from_secs(9)));
    // The caller's `ia` is floored in place too (the value the overlay reads).
    assert_eq!(ia.atime, Timespec64::from_secs(5));
    assert_eq!(ia.mtime, Timespec64::from_secs(7));
    assert_eq!(ia.ctime, Timespec64::from_secs(9));
}

/// A 1 ns granularity (the default) is the identity: nothing is perturbed.
#[test]
fn ns_gran_is_identity() {
    let (inode, raw) = make_timed(Some(sb_with_gran(1)));
    let t_a = Timespec64::new(3, 111);
    let t_m = Timespec64::new(4, 222);
    let mut ia = Iattr {
        valid: ATTR_ATIME | ATTR_MTIME | ATTR_ATIME_SET | ATTR_MTIME_SET,
        atime: t_a, mtime: t_m, ctime: Timespec64::new(5, 7),
        ..Default::default()
    };
    notify_change(&Idmap::identity(), &inode, &mut ia, &Cred::root()).unwrap();
    assert_eq!(raw.recorded(), (Some(t_a), Some(t_m), Timespec64::new(5, 7)));
}

/// Only the time fields named in `valid` are floored / written; an omitted
/// field (UTIME_OMIT) is left `None`, not flattened to a floored zero.
#[test]
fn omitted_field_not_written() {
    let (inode, raw) = make_timed(Some(sb_with_gran(NSEC_PER_SEC)));
    let mut ia = Iattr {
        valid: ATTR_MTIME | ATTR_MTIME_SET,
        mtime: Timespec64::new(8, 500_000_000),
        ctime: Timespec64::new(8, 500_000_000),
        ..Default::default()
    };
    notify_change(&Idmap::identity(), &inode, &mut ia, &Cred::root()).unwrap();
    let (a, m, c) = raw.recorded();
    assert_eq!(a, None, "atime omitted → left alone");
    assert_eq!(m, Some(Timespec64::from_secs(8)), "mtime floored to whole second");
    assert_eq!(c, Timespec64::from_secs(8), "ctime floored alongside the mtime change");
    // The untouched atime field is never floored.
    assert_eq!(ia.atime, Timespec64::ZERO);
}

/// An inode with no backing superblock keeps full-ns precision (granularity is
/// implicitly 1 ns) — the `i_sb` guard skips truncation entirely.
#[test]
fn no_sb_keeps_full_ns() {
    let (inode, raw) = make_timed(None);
    let t_a = Timespec64::new(6, 654_321);
    let t_m = Timespec64::new(6, 123_456);
    let mut ia = Iattr {
        valid: ATTR_ATIME | ATTR_MTIME | ATTR_ATIME_SET | ATTR_MTIME_SET,
        atime: t_a, mtime: t_m, ctime: Timespec64::new(6, 1),
        ..Default::default()
    };
    notify_change(&Idmap::identity(), &inode, &mut ia, &Cred::root()).unwrap();
    assert_eq!(raw.recorded(), (Some(t_a), Some(t_m), Timespec64::new(6, 1)));
}

/// F767: a PRE-1970 specific-time setattr flows through `notify_change` to the
/// backend untouched — no `EINVAL`, no reinterpretation as a huge positive.
/// This is the `tar -x` / `rsync --times` / `cp -p` case on a historical
/// archive. Granularity flooring still applies, and still only to `tv_nsec`.
#[test]
fn pre_epoch_specific_times_reach_the_backend() {
    let (inode, raw) = make_timed(Some(sb_with_gran(1)));
    let t_a = Timespec64::new(-2_000_000_000, 123_456_789); // 1906-08-16
    let t_m = Timespec64::new(-1, 999_999_999);             // 1969-12-31T23:59:59.999999999
    let mut ia = Iattr {
        valid: ATTR_ATIME | ATTR_MTIME | ATTR_ATIME_SET | ATTR_MTIME_SET | ATTR_CTIME,
        atime: t_a, mtime: t_m, ctime: Timespec64::new(-5, 1),
        ..Default::default()
    };
    notify_change(&Idmap::identity(), &inode, &mut ia, &Cred::root()).unwrap();
    assert_eq!(raw.recorded(), (Some(t_a), Some(t_m), Timespec64::new(-5, 1)),
        "negative seconds reach the backend verbatim at ns granularity");
    // And the inode reads them back unchanged.
    assert_eq!(inode.atime(), Some(t_a));
    assert_eq!(inode.mtime(), Some(t_m));
}

/// F767: second-granularity flooring of a pre-epoch specific time keeps the
/// second. A whole-value floor over a signed ns scalar would land on -3, not -2.
#[test]
fn pre_epoch_second_gran_keeps_the_second() {
    let (inode, raw) = make_timed(Some(sb_with_gran(NSEC_PER_SEC)));
    let mut ia = Iattr {
        valid: ATTR_MTIME | ATTR_MTIME_SET | ATTR_CTIME,
        mtime: Timespec64::new(-2, 500_000_000),
        ctime: Timespec64::new(-2, 500_000_000),
        ..Default::default()
    };
    notify_change(&Idmap::identity(), &inode, &mut ia, &Cred::root()).unwrap();
    let (_, m, c) = raw.recorded();
    assert_eq!(m, Some(Timespec64::from_secs(-2)), "sec stays -2, nsec zeroed");
    assert_eq!(c, Timespec64::from_secs(-2));
    assert_eq!(inode.mtime(), Some(Timespec64::from_secs(-2)));
}
