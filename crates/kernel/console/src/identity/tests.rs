// A console tty inode is what its `i_private` says it is. These pin that the
// resolver DECLINES every inode the console layer did not build — the property
// `handle_tty_ioctl` turns into ENOTTY, matching Linux, where `tty_ioctl` is
// reachable only through `tty_fops` and a description without an
// `->unlocked_ioctl` gets `-ENOTTY` from `vfs_ioctl`. Verified against the
// primary kernel sources: `signalfd_fops` and `eventfd_fops` declare no
// `.unlocked_ioctl` at all, and `timerfd`'s / `inotify`'s ioctl handlers
// return `-ENOTTY` from their default arm.

use alloc::sync::Arc;

use vfs::pseudo_ino::{CONSOLE_TTY, EPOLL, EVDEV, INOTIFY, SIGNALFD, TIMERFD};
use vfs::{default_file_ops, default_inode_ops, mk_mode, FileType, InodeBuilder, InodeRef};

use crate::identity::{binding_of, is_console_tty, TtyBinding};
use crate::ids;
use crate::nodes::{make_console_inode, make_serial_inode, make_system_console_inode,
                   make_tty_alias_inode};

/// A CharDev inode with no console backend state — the shape every anon-inode
/// family (signalfd, timerfd, inotify, epoll, bpf) presents to the ioctl
/// dispatcher's unclaimed-CharDev fallback.
fn anon_chardev(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::CharDev, 0o600), default_inode_ops(),
                      default_file_ops())
        .build()
}

#[test]
fn every_console_node_resolves_to_its_own_binding() {
    assert_eq!(binding_of(&make_serial_inode()), Some(TtyBinding::Serial));
    assert_eq!(binding_of(&make_console_inode(0)), Some(TtyBinding::ForegroundVt),
        "/dev/tty0 follows the foreground VT");
    assert_eq!(binding_of(&make_tty_alias_inode()), Some(TtyBinding::ForegroundVt),
        "/dev/tty follows the foreground VT");
    assert_eq!(binding_of(&make_system_console_inode()), Some(TtyBinding::PreferredConsole),
        "/dev/console follows the preferred console, not a hardcoded VT");
    for vt in 1..=ids::MAX_VT_INO_LB {
        assert_eq!(binding_of(&make_console_inode(vt)), Some(TtyBinding::Vt(vt)),
            "/dev/tty{vt} pins VT {vt}");
    }
}

#[test]
fn a_signalfd_shaped_chardev_is_not_a_tty() {
    // The exact miss: signalfd inodes are CharDev, land in the ioctl
    // dispatcher's unclaimed-CharDev fallback, and `ino & 0xFF` of
    // 0x7200_0000 is 0 — which the old `n => Vt(n)` arm answered from a
    // fabricated VT instead of declining.
    let sfd = anon_chardev(SIGNALFD.start());
    assert_eq!(binding_of(&sfd), None, "a signalfd is not a console tty");
    assert!(!is_console_tty(&sfd));
}

#[test]
fn no_anon_inode_family_resolves_as_a_console_tty() {
    // Walk low bytes 0..=0xFF of each family so the ones that land inside the
    // 1..=63 VT selector range (and on the four named selectors) are covered.
    for base in [SIGNALFD.start(), TIMERFD.start(), INOTIFY.start(), EPOLL.start(),
                 EVDEV.start()] {
        for lb in 0..=0xFFu64 {
            let i = anon_chardev(base + lb);
            assert_eq!(binding_of(&i), None,
                "anon inode {:#x} must not resolve as a tty", base + lb);
        }
    }
}

#[test]
fn a_foreign_inode_with_a_console_tty_number_is_rejected() {
    let real = make_console_inode(1);
    let fake = anon_chardev(real.ino());
    assert_eq!(fake.ino(), real.ino(), "the lookalike copies the number exactly");
    assert_eq!(binding_of(&fake), None, "an inode number is not proof of tty ownership");
}

#[test]
fn console_and_tty1_no_longer_share_one_number() {
    // `/dev/console`'s selector used to be 0x01 — the same number `/dev/tty1`
    // carries, on the same `st_dev`.
    let console = make_system_console_inode();
    for vt in 1..=ids::MAX_VT_INO_LB {
        assert_ne!(console.ino(), make_console_inode(vt).ino(),
            "/dev/console aliases /dev/tty{vt}");
    }
}

#[test]
fn every_minted_number_stays_inside_the_console_region() {
    let mut nodes = alloc::vec![make_serial_inode(), make_tty_alias_inode(),
                                make_system_console_inode(), make_console_inode(0)];
    for vt in 1..=ids::MAX_VT_INO_LB { nodes.push(make_console_inode(vt)); }
    for n in &nodes {
        assert!(CONSOLE_TTY.contains(n.ino()), "{:#x} inside CONSOLE_TTY", n.ino());
        assert!(is_console_tty(n));
    }
    // …and every one of them is a distinct identity.
    let mut inos: alloc::vec::Vec<u64> = nodes.iter().map(|n| n.ino()).collect();
    inos.sort_unstable();
    let len = inos.len();
    inos.dedup();
    assert_eq!(inos.len(), len, "two console devices share one st_ino");
}

#[test]
fn console_data_is_the_only_thing_that_makes_a_tty() {
    // Arc-ing an unrelated payload into i_private must not be mistaken for it.
    let i = InodeBuilder::new(ids::tty_ino(1), mk_mode(FileType::CharDev, 0o620),
                              default_inode_ops(), default_file_ops())
        .private(Arc::new(0u64))
        .build();
    assert_eq!(binding_of(&i), None);
}
