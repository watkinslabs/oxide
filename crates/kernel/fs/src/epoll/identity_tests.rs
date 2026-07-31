// "Which file is an epoll file" must not be answerable from an inode NUMBER.
// The pseudo-inode ranges subsystems mint from are not partitioned, and
// `/dev/input/eventN` draws from the same one this module does — so a numeric
// test reported an evdev fd as a live epoll instance, and every evdev ioctl
// came back EINVAL from `ep_eventpoll_ioctl` while `epoll_ctl` mutated an
// unrelated instance. These assert identity comes from the inode's own state.

use alloc::sync::Arc;
use vfs::{default_inode_ops, mk_mode, FileType, Ino, InodeBuilder, InodeRef};

use super::{epoll_data_of_inode, make_epoll_inode, INO_REGION};

/// The inode number `/dev/input/event0` carried while evdev minted from
/// epoll's base — the number that made a numeric test report an evdev fd as a
/// live epoll instance. Named here, not imported, so the driver crate stays
/// out of this crate's dependency graph.
const EVDEV_EVENT0_INO_BEFORE_THE_SPLIT: Ino = 0x7400_0001;

struct ForeignState;

/// One inode carrying `ino` and backend state that is not `EpollData`.
fn foreign_inode(ino: Ino) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::CharDev, 0), default_inode_ops(),
        vfs::default_file_ops())
        .private(Arc::new(ForeignState))
        .build()
}

/// evdev now declares its own range, so the two no longer share numbers — but
/// that is a numbering guarantee, not an identity one, and the tests below
/// still hold when it is withdrawn.
#[test]
fn epoll_and_evdev_declare_disjoint_ranges() {
    assert!(!vfs::pseudo_ino::overlaps(&INO_REGION, &vfs::pseudo_ino::EVDEV));
    // The state the bug was found in: evdev's first device number sat squarely
    // inside epoll's range.
    assert!(INO_REGION.contains(EVDEV_EVENT0_INO_BEFORE_THE_SPLIT));
}

/// Every number epoll can mint stays inside its own range, however many
/// instances a process opens.
#[test]
fn minted_numbers_stay_inside_the_region() {
    for id in [0u64, 1, 7, INO_REGION.len() - 1, INO_REGION.len(), INO_REGION.len() * 3 + 5] {
        assert!(INO_REGION.contains(INO_REGION.at(id)), "id {id} left the region");
    }
}

#[test]
fn a_real_epoll_inode_resolves() {
    let inode = make_epoll_inode();
    assert!(epoll_data_of_inode(&inode).is_some());
}

#[test]
fn an_evdev_inode_never_resolves_as_epoll() {
    // Mint a real epoll instance first so the id the number decodes to is
    // occupied — the exact state in which the numeric test handed an evdev fd
    // somebody else's epoll.
    let _live = make_epoll_inode();
    assert!(epoll_data_of_inode(&foreign_inode(EVDEV_EVENT0_INO_BEFORE_THE_SPLIT)).is_none());
}

#[test]
fn a_foreign_inode_reusing_an_epoll_number_never_resolves() {
    let real = make_epoll_inode();
    let ino = real.ino();
    assert!(epoll_data_of_inode(&real).is_some());
    assert!(epoll_data_of_inode(&foreign_inode(ino)).is_none());
}

#[test]
fn an_inode_outside_the_range_still_resolves_when_it_owns_epoll_state() {
    // The converse guard: identity follows the state, not the number, so an
    // epoll inode would keep working even if the range were renumbered.
    let inode = make_epoll_inode();
    assert!(epoll_data_of_inode(&inode).is_some());
    assert!(epoll_data_of_inode(&foreign_inode(0)).is_none());
}
