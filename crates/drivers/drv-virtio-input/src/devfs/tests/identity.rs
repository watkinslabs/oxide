// An evdev file is identified by the backend state its inode owns, never by
// the inode NUMBER. A numeric test let a foreign inode into this handler,
// where the file's unrelated `private_data` word would be read back as an
// `EvdevOpen`. The numbers themselves used to collide with epoll's — both minted
// from 0x7400_0000, so `/dev/input/event0` and epoll's first instance reported
// the same `st_ino` — and now come from evdev's own declared region.

use alloc::sync::Arc;
use vfs::pseudo_ino::{EPOLL, EVDEV};
use vfs::{default_file_ops, default_inode_ops, mk_mode, Dentry, File, FileType, Ino,
          InodeBuilder, OpenFlags};

use super::*;
use crate::devfs::handle_evdev_ioctl;

/// The number `make_evdev_inode_for` gives `/dev/input/event0`.
const EVENT0_INO: Ino = EVDEV.start() + crate::EVDEV_FIRST_INO_OFFSET;

struct ForeignState;

/// A file that is NOT an evdev client but whose inode reuses evdev's number.
fn foreign_file(ino: Ino) -> Arc<File> {
    let inode = InodeBuilder::new(ino, mk_mode(FileType::CharDev, 0), default_inode_ops(),
        default_file_ops())
        .private(Arc::new(ForeignState))
        .build();
    File::new(inode.clone(), Dentry::new_anon(inode), OpenFlags::O_RDONLY)
}

#[test]
fn evdev_numbers_no_longer_alias_epoll_s() {
    // `stat` on `/dev/input/event0` and on an epoll fd reported the same
    // `st_ino` while both bases were 0x7400_0000. Identity never depended on
    // the number, but two owners minting the same one is its own defect.
    assert!(EVDEV.contains(EVENT0_INO));
    assert!(!EPOLL.contains(EVENT0_INO));
    assert!(!EPOLL.contains(EVDEV.start()));
    assert!(!EPOLL.contains(EVDEV.end()));
}

#[test]
fn a_published_evdev_inode_number_falls_inside_the_evdev_region() {
    const REQUESTED_ID: u32 = 11;
    let key = test_dev(REQUESTED_ID).device_key;
    let _ = crate::remove_device(key);
    let (_, id) = crate::install(test_dev(REQUESTED_ID)).expect("install identity model");
    let ino = crate::devfs::make_evdev_inode(id).ino();
    assert!(EVDEV.contains(ino), "{ino:#x} outside {}", EVDEV.name());
    assert_eq!(crate::remove_device(key), Some(id));
}

#[test]
fn a_foreign_inode_sharing_evdev_s_number_is_declined() {
    // EVIOCGBIT(0, 8) — libinput's first question of any device.
    let request = evio_read(crate::EVIOCGBIT_BASE_NR as u32, 8);
    let mut out = [0u8; 8];
    let file = foreign_file(EVENT0_INO);
    assert_eq!(handle_evdev_ioctl(&file, request, out.as_mut_ptr() as u64), None);
}

#[test]
fn every_evdev_number_shape_is_declined_for_a_foreign_inode() {
    let mut out = [0u8; crate::EVDEV_STATE_BYTES];
    for ino in [EVENT0_INO, EVDEV.start(), EVDEV.start() + 2, EVDEV.end()] {
        let file = foreign_file(ino);
        for nr in [crate::EVIOCGVERSION_NR, crate::EVIOCGID_NR, crate::EVIOCGNAME_NR,
                   crate::EVIOCGBIT_BASE_NR, crate::EVIOCGABS_BASE_NR] {
            let request = evio_read(nr as u32, out.len());
            assert_eq!(handle_evdev_ioctl(&file, request, out.as_mut_ptr() as u64), None,
                "ino {ino:#x} nr {nr:#x}");
        }
    }
}

#[test]
fn a_real_evdev_file_answers_the_capability_query() {
    // The exact request the boot showed failing: EVIOCGBIT(0, 8), "which event
    // types does this device support". A device that answers it reports the
    // number of capability bytes copied, never an error.
    const REQUESTED_ID: u32 = 9;
    let key = test_dev(REQUESTED_ID).device_key;
    let _ = crate::remove_device(key);
    let mut model = test_dev(REQUESTED_ID);
    model.ev_bits[0] |= 1 << crate::EV_KEY;
    let (_, id) = crate::install(model).expect("install identity model");
    let file = test_file(id);
    let mut out = [0u8; 8];
    let request = evio_read(crate::EVIOCGBIT_BASE_NR as u32, out.len());
    let rv = handle_evdev_ioctl(&file, request, out.as_mut_ptr() as u64);
    assert!(matches!(rv, Some(n) if n > 0), "EVIOCGBIT(0, 8) -> {rv:?}");
    assert_eq!(crate::remove_device(key), Some(id));
}

#[test]
fn an_unknown_evdev_command_is_einval_not_enotty() {
    // `evdev_do_ioctl` ends in `return -EINVAL`; ENOTTY is not an errno evdev
    // produces, and returning it would also hand the command to a later
    // dispatch stage that has no business answering for this device.
    // 0x11 names no evdev command: past the string/property queries and short
    // of the device-state block.
    const UNASSIGNED_NR: u32 = 0x11;
    const REQUESTED_ID: u32 = 10;
    let key = test_dev(REQUESTED_ID).device_key;
    let _ = crate::remove_device(key);
    let (_, id) = crate::install(test_dev(REQUESTED_ID)).expect("install identity model");
    let file = test_file(id);
    let mut out = [0u8; 8];
    let request = evio_read(UNASSIGNED_NR, out.len());
    assert_eq!(handle_evdev_ioctl(&file, request, out.as_mut_ptr() as u64),
        Some(-(syscall::errno::Errno::Einval.as_i32() as i64)));
    assert_eq!(crate::remove_device(key), Some(id));
}

#[test]
fn a_non_evdev_command_group_still_falls_through() {
    // Only the 'E' group belongs to evdev; the generic VFS commands stay with
    // the stage that owns them.
    let file = test_file(0);
    const TIOCGWINSZ: u64 = 0x5413;
    assert_eq!(handle_evdev_ioctl(&file, TIOCGWINSZ, 0), None);
}
