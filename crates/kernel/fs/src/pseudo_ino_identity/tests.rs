use alloc::sync::Arc;

use vfs::pseudo_ino::{
    Region, EVENTFD, INOTIFY, PERF, PIPE, SIGNALFD, TIMERFD, USERFAULTFD,
};
use vfs::{default_file_ops, default_inode_ops, mk_mode, FileType, Ino, InodeBuilder, InodeRef};

/// State no family in this crate owns, so an inode carrying it is foreign to
/// every identity gate under test.
struct ForeignState;

/// An inode carrying `ino` and backend state that belongs to nobody.
fn foreign_inode(ino: Ino) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0), default_inode_ops(), default_file_ops())
        .private(Arc::new(ForeignState))
        .build()
}

/// Every number a region-folded minter can produce stays inside the region,
/// including well past its length.
fn stays_inside(r: &Region) {
    for n in [0u64, 1, 1024, r.len() - 1, r.len(), r.len() + 1, r.len() * 7 + 3, u64::MAX] {
        assert!(r.contains(r.at(n)), "{}: index {n} left the region", r.name());
    }
}

// ---------------------------------------------------------------------------
// userfaultfd — the ioctl router used to admit by the inode number's high half.
// ---------------------------------------------------------------------------

fn a_uffd() -> InodeRef {
    crate::userfaultfd::make_userfaultfd_inode(0, alloc::sync::Weak::new())
}

#[test]
fn a_real_userfaultfd_resolves() {
    assert!(crate::userfaultfd::is_uffd_inode(&a_uffd()));
}

/// The type-confusion case: a foreign inode carrying a userfaultfd's exact
/// number. Admitting it handed `handle_uffd_ioctl` an unrelated `i_private`.
#[test]
fn a_foreign_inode_reusing_a_userfaultfd_number_is_refused() {
    let real = a_uffd();
    assert!(USERFAULTFD.contains(real.ino()));
    assert!(!crate::userfaultfd::is_uffd_inode(&foreign_inode(real.ino())));
    // …and the region's base, the number the old high-half test keyed on.
    assert!(!crate::userfaultfd::is_uffd_inode(&foreign_inode(USERFAULTFD.start())));
}

#[test]
fn userfaultfd_numbers_stay_inside_their_region() {
    for _ in 0..64 { assert!(USERFAULTFD.contains(a_uffd().ino())); }
    stays_inside(&USERFAULTFD);
}

// ---------------------------------------------------------------------------
// perf — `is_perf_inode` tested the number while `event_of` beside it already
// answered from state.
// ---------------------------------------------------------------------------

#[test]
fn a_foreign_inode_reusing_a_perf_number_is_refused() {
    assert!(!crate::perf::is_perf_inode(&foreign_inode(PERF.start())));
    assert!(!crate::perf::is_perf_inode(&foreign_inode(PERF.at(1))));
    assert!(!crate::perf::is_perf_inode(&foreign_inode(PERF.end())));
}

/// The gate and the lifter must never disagree — the shape of the original
/// defect, where one asked the number and the other asked the state.
#[test]
fn the_perf_gate_and_the_perf_lifter_agree() {
    let foreign = foreign_inode(PERF.at(3));
    assert_eq!(crate::perf::is_perf_inode(&foreign), crate::perf::event_of(&foreign).is_some());
}

#[test]
fn perf_numbers_stay_inside_their_region() { stays_inside(&PERF); }

// ---------------------------------------------------------------------------
// signalfd / inotify — every instance used to carry one shared number.
// ---------------------------------------------------------------------------

#[test]
fn two_signalfds_get_different_inode_numbers() {
    let a = crate::signalfd::make_signalfd_inode(0);
    let b = crate::signalfd::make_signalfd_inode(0);
    assert_ne!(a.ino(), b.ino(), "every signalfd carried the same st_ino");
    assert!(SIGNALFD.contains(a.ino()));
    assert!(SIGNALFD.contains(b.ino()));
}

#[test]
fn a_burst_of_signalfds_are_all_distinct_and_inside_the_region() {
    let mut seen = alloc::collections::BTreeSet::new();
    for _ in 0..256 {
        let ino = crate::signalfd::make_signalfd_inode(0).ino();
        assert!(SIGNALFD.contains(ino));
        assert!(seen.insert(ino), "duplicate signalfd ino {ino:#x}");
    }
}

#[test]
fn two_inotify_groups_get_different_inode_numbers() {
    let a = crate::inotify::make_inotify_inode(crate::inotify::InotifyData::new(0));
    let b = crate::inotify::make_inotify_inode(crate::inotify::InotifyData::new(0));
    assert_ne!(a.ino(), b.ino(), "every inotify group carried the same st_ino");
    assert!(INOTIFY.contains(a.ino()));
    assert!(INOTIFY.contains(b.ino()));
}

// ---------------------------------------------------------------------------
// The remaining counter-based families in this crate.
// ---------------------------------------------------------------------------

#[test]
fn pipe_numbers_stay_inside_their_region() {
    for _ in 0..64 { assert!(PIPE.contains(crate::pipe::make_pipe_inode().ino())); }
    stays_inside(&PIPE);
}

#[test]
fn eventfd_numbers_stay_inside_their_region() {
    for _ in 0..64 { assert!(EVENTFD.contains(crate::pipe::make_eventfd_inode(0, false).ino())); }
    stays_inside(&EVENTFD);
}

#[test]
fn timerfd_and_epoll_numbers_stay_inside_their_regions() {
    stays_inside(&TIMERFD);
    stays_inside(&vfs::pseudo_ino::EPOLL);
}

/// bpf minted from timerfd's base: a bpf prog fd and a process's third timerfd
/// carried the same number. The two ranges must now be disjoint.
#[test]
fn bpf_and_timerfd_numbers_no_longer_intersect() {
    assert!(!vfs::pseudo_ino::overlaps(&TIMERFD, &vfs::pseudo_ino::BPF));
    for low in [0x01u64, 0x02, 0x03, 0x04, 0x05] {
        assert!(!TIMERFD.contains(vfs::pseudo_ino::BPF.start() | low));
    }
}
