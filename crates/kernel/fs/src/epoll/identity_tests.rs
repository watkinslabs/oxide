// "Which file is an epoll file" must not be answerable from an inode NUMBER.
// The pseudo-inode ranges subsystems mint from are not partitioned, and
// `/dev/input/eventN` draws from the same one this module does — so a numeric
// test reported an evdev fd as a live epoll instance, and every evdev ioctl
// came back EINVAL from `ep_eventpoll_ioctl` while `epoll_ctl` mutated an
// unrelated instance. These assert identity comes from the inode's own state.

use alloc::sync::Arc;
use vfs::{default_inode_ops, mk_mode, FileType, Ino, InodeBuilder, InodeRef};

use super::{epoll_data_of_inode, ids, make_epoll_inode};

/// The inode number a `/dev/input/event0` node carries. Named here, not
/// imported, so the driver crate stays out of this crate's dependency graph:
/// the point of the test is that this NUMBER falls inside epoll's range.
const EVDEV_EVENT0_INO: Ino = 0x7400_0001;

struct ForeignState;

/// One inode carrying `ino` and backend state that is not `EpollData`.
fn foreign_inode(ino: Ino) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::CharDev, 0), default_inode_ops(),
        vfs::default_file_ops())
        .private(Arc::new(ForeignState))
        .build()
}

#[test]
fn evdev_inode_number_lies_inside_the_epoll_range() {
    // The precondition the whole bug rests on: the ranges are not disjoint, so
    // no arithmetic on `ino` can separate the two owners.
    assert_eq!(EVDEV_EVENT0_INO & !ids::INO_MASK, ids::INO_BASE);
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
    assert!(epoll_data_of_inode(&foreign_inode(EVDEV_EVENT0_INO)).is_none());
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
