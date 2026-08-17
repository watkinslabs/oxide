//! The quota hooks, and the two halves of them that can be driven hosted.
//!
//! Installing them needs a mounted filesystem, which needs a block device, so
//! the hook objects themselves are out of reach here. What is not is the
//! decision they are built from — which kinds get enabled — and the record
//! conversion they read and write through, which is where a unit or a field
//! that only one side applies would show.

use super::*;
use crate::opts::Options;
use crate::quota::{Dqblk, Enforcement, Setup};
use crate::test_image::quota_image as qi;
use crate::test_image::{self, nodes};
use crate::uapi::{BLKSIZE, MAX_QUOTAS};
use crate::volume::quotas::{GRPQUOTA, PRJQUOTA, USRQUOTA};
use crate::volume::Volume;
use alloc::vec::Vec;
use sectors::MemImage;
use syscall::errno::Errno;

const UID: u32 = 4242;
const QUOTA_INO: u32 = 9;

fn accounted(fmt: u32) -> Setup {
    Setup { ino: QUOTA_INO, enforcement: Enforcement::Usage, fmt, named: false }
}

/// A volume whose user-quota file holds one record for `UID`.
fn vol() -> Volume<MemImage> {
    let file = qi::user_file(UID, 0, 0);
    let mut b = test_image::with_root();
    b.feature |= crate::flags::FEATURE_QUOTA_INO;
    b.qf_ino[USRQUOTA] = QUOTA_INO;
    let blocks: Vec<(u64, Vec<u8>)> =
        file.chunks(BLKSIZE).enumerate().map(|(i, c)| (i as u64, c.to_vec())).collect();
    nodes::add_sparse_file(&mut b, QUOTA_INO, file.len() as u64, &blocks);
    let mut o = Options::defaults();
    o.usrquota = true;
    b.mount_opts(o).unwrap()
}

#[test]
fn only_the_kinds_the_volume_accounts_are_enabled() {
    let setups = [accounted(1), Setup::OFF, accounted(2)];
    let plan = enable_plan(&setups);
    assert_eq!(plan[USRQUOTA], Some(1), "an accounted kind was left disabled");
    assert_eq!(plan[GRPQUOTA], None, "a kind with no file behind it was enabled");
    assert_eq!(plan[PRJQUOTA], Some(2), "the format did not reach the interface");
}

#[test]
fn a_volume_that_accounts_nothing_enables_nothing() {
    let plan = enable_plan(&[Setup::OFF; MAX_QUOTAS]);
    assert!(plan.iter().all(Option::is_none), "a kind was enabled with no file behind it");
}

#[test]
fn a_record_survives_the_round_trip_through_the_interfaces_form() {
    let d = Dqblk {
        bhardlimit: 9 * BLKSIZE as u64,
        bsoftlimit: 4 * BLKSIZE as u64,
        curspace: 3 * BLKSIZE as u64,
        rsvspace: BLKSIZE as u64,
        ihardlimit: 40,
        isoftlimit: 20,
        curinodes: 7,
        btime: 1_800_000_123,
        itime: 1_800_000_456,
    };
    assert_eq!(from_mem(&to_mem(&d)), d, "a field is lost crossing the interface");
}

#[test]
fn an_expiry_the_interface_reports_as_negative_reads_as_no_grace() {
    // The stored field is unsigned, so a negative expiry cannot be written to
    // it; wrapping would put the grace billions of seconds into the future.
    let mut m = to_mem(&Dqblk::default());
    m.dqb_btime = -1;
    m.dqb_itime = -9;
    let d = from_mem(&m);
    assert_eq!((d.btime, d.itime), (0, 0));
}

#[test]
fn the_next_identity_a_kind_holds_a_record_for_comes_off_the_tree() {
    let mut v = vol();
    let (id, rec) = v.quota_next_record(USRQUOTA, 0).unwrap().expect("the fixture holds a record");
    assert_eq!(id, UID);
    assert_eq!(rec, v.quota_record(USRQUOTA, UID).unwrap());
    assert!(v.quota_next_record(USRQUOTA, UID + 1).unwrap().is_none(), "an identity past the last");
}

#[test]
fn a_kind_the_volume_does_not_account_has_no_next_identity_rather_than_an_empty_one() {
    let mut v = vol();
    assert_eq!(v.quota_next_record(GRPQUOTA, 0), Err(Errno::Esrch));
    assert_eq!(v.quota_next_record(MAX_QUOTAS, 0), Err(Errno::Einval));
}

#[test]
fn a_record_set_through_the_interface_is_what_the_next_allocation_is_measured_against() {
    // The cache is the truth a charge consults, so a limit set here has to
    // take effect on the very next allocation rather than at the next
    // checkpoint. Writing the file and leaving the cache alone would enforce
    // the old limit until something evicted it.
    let mut v = vol();
    let mut d = v.quota_record(USRQUOTA, UID).unwrap();
    d.bhardlimit = 16 * BLKSIZE as u64;
    v.set_quota_record(USRQUOTA, UID, d).unwrap();
    assert_eq!(v.quota_record(USRQUOTA, UID).unwrap().bhardlimit, 16 * BLKSIZE as u64);
    assert!(v.is_dirty(), "a changed record left nothing for the checkpoint to write");
}

/// A record waiting for the next checkpoint is a condition the volume is in,
/// and the status word says so. It is DERIVED from the outstanding records
/// rather than stored beside them, so it cannot say "none" while some are
/// waiting.
#[test]
fn an_outstanding_record_shows_in_the_condition_word() {
    use crate::sbflags::bits::QUOTA_NEED_FLUSH;
    let mut v = vol();
    assert_eq!(v.sb_status() & (1 << QUOTA_NEED_FLUSH), 0, "nothing outstanding yet");
    let mut d = v.quota_record(USRQUOTA, UID).unwrap();
    d.bhardlimit = 16 * BLKSIZE as u64;
    v.set_quota_record(USRQUOTA, UID, d).unwrap();
    assert_ne!(v.sb_status() & (1 << QUOTA_NEED_FLUSH), 0);
    // The checkpoint writes them, and the condition goes with them.
    v.commit().unwrap();
    assert_eq!(v.sb_status() & (1 << QUOTA_NEED_FLUSH), 0);
}

#[test]
fn a_record_may_not_be_set_on_a_kind_the_volume_does_not_account() {
    let mut v = vol();
    assert_eq!(v.set_quota_record(GRPQUOTA, UID, Dqblk::default()), Err(Errno::Esrch));
    assert_eq!(v.set_quota_record(MAX_QUOTAS, UID, Dqblk::default()), Err(Errno::Einval));
}
