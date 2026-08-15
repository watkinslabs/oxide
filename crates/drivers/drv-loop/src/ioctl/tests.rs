use super::*;
use block::BlockDevice as _;
use crate::testing::Mem;
use crate::uapi::{LO_FLAGS_AUTOCLEAR, LO_FLAGS_DIRECT_IO, LO_FLAGS_PARTSCAN, LO_FLAGS_READ_ONLY,
                  LO_CRYPT_XOR, LO_NAME_SIZE};

fn dev() -> LoopDevice { LoopDevice::new(4) }

fn info(f: impl FnOnce(&mut LoopInfo64)) -> LoopInfo64 {
    let mut i = LoopInfo64::default();
    f(&mut i);
    i
}

/// The plain bind: a whole file, writable, default block size.
#[test]
fn set_fd_binds_the_whole_file() {
    let d = dev();
    assert_eq!(set_fd(&d, Mem::new(8192), true), Ok(()));
    let status = get_status(&d).expect("bound");
    assert_eq!((status.lo_offset, status.lo_sizelimit, status.lo_flags), (0, 0, 0));
    assert_eq!(status.lo_number, 4, "the device reports its own number");
    assert_eq!(d.capacity_blocks(), 16);
}

/// Binding a description that cannot be written yields a read-only device,
/// and the caller can see that in the status it reads back — not discover it
/// on its first write.
#[test]
fn a_read_only_description_is_visible_in_the_status() {
    let d = dev();
    assert_eq!(set_fd(&d, Mem::with(alloc::vec![0; 4096], false), false), Ok(()));
    assert_eq!(get_status(&d).unwrap().lo_flags & LO_FLAGS_READ_ONLY, LO_FLAGS_READ_ONLY);
}

/// Configure applies the window, and the device is sized by it immediately.
#[test]
fn configure_applies_the_window_at_bind_time() {
    let d = dev();
    let i = info(|i| { i.lo_offset = 1024; i.lo_sizelimit = 2048; });
    assert_eq!(configure(&d, Mem::new(8192), true, i, 1024), Ok(()));
    assert_eq!(d.capacity_blocks(), 4, "2 KiB window");
    let (_, _, bsize) = d.status().unwrap();
    assert_eq!(bsize, 1024);
}

/// Refusal order: an invalid window is reported before an invalid flag, and
/// an invalid flag before an invalid block size. A request wrong in several
/// ways reports the same one every time.
#[test]
fn configure_refuses_in_a_fixed_order() {
    let d = dev();
    let all_wrong = info(|i| { i.lo_encrypt_type = LO_CRYPT_XOR; i.lo_flags = 1 << 20; });
    assert_eq!(configure(&d, Mem::new(4096), true, all_wrong, 999), Err(Errno::Einval));
    let bad_flag_and_size = info(|i| i.lo_flags = 1 << 20);
    assert_eq!(configure(&d, Mem::new(4096), true, bad_flag_and_size, 999), Err(Errno::Einval));
    let bad_size_only = info(|i| i.lo_flags = LO_FLAGS_PARTSCAN);
    assert_eq!(configure(&d, Mem::new(4096), true, bad_size_only, 999), Err(Errno::Einval));
    // ...and a refused request binds nothing.
    assert!(!d.is_bound());
}

/// A window whose fields overflow the signed range is `EOVERFLOW`, which is
/// how a caller distinguishes "impossible window" from "malformed request".
#[test]
fn an_overflowing_window_is_reported_as_overflow() {
    let d = dev();
    assert_eq!(configure(&d, Mem::new(4096), true, info(|i| i.lo_offset = u64::MAX), 0),
               Err(Errno::Eoverflow));
}

/// Clearing an unbound device says so rather than reporting success, so a
/// caller can tell whether it was the one that released the file.
#[test]
fn clearing_an_unbound_device_reports_enxio() {
    let d = dev();
    assert_eq!(clr_fd(&d), Err(Errno::Enxio));
    assert_eq!(get_status(&d).err(), Some(Errno::Enxio));
    assert_eq!(set_capacity(&d), Err(Errno::Enxio));
    assert_eq!(set_block_size(&d, 1024), Err(Errno::Enxio));
    set_fd(&d, Mem::new(4096), true).unwrap();
    assert_eq!(clr_fd(&d), Ok(()));
    assert_eq!(clr_fd(&d), Err(Errno::Enxio), "the second clear is a no-op that says so");
}

/// `SET_STATUS` moves the window and resizes the device with it.
#[test]
fn set_status_moves_the_window_and_resizes() {
    let d = dev();
    set_fd(&d, Mem::new(8192), true).unwrap();
    assert_eq!(d.capacity_blocks(), 16);
    set_status(&d, info(|i| { i.lo_offset = 4096; })).unwrap();
    assert_eq!(d.capacity_blocks(), 8);
    assert_eq!(get_status(&d).unwrap().lo_offset, 4096);
}

/// A status update that does not move the window leaves it exactly where it
/// was, even though the request carries window fields.
#[test]
fn a_status_update_that_does_not_move_the_window_leaves_it_alone() {
    let d = dev();
    let i = info(|i| { i.lo_offset = 1024; i.lo_sizelimit = 2048; });
    configure(&d, Mem::new(8192), true, i, 0).unwrap();
    let before = d.capacity_blocks();
    let rename = info(|i| { i.lo_offset = 1024; i.lo_sizelimit = 2048; i.lo_file_name[0] = b'x'; });
    set_status(&d, rename).unwrap();
    assert_eq!(d.capacity_blocks(), before);
    let status = get_status(&d).unwrap();
    assert_eq!((status.lo_offset, status.lo_sizelimit), (1024, 2048));
    assert_eq!(status.lo_file_name[0], b'x', "the name did move");
}

/// A status update cannot make a read-only device writable — the flag was
/// fixed by the description it was bound to.
#[test]
fn set_status_cannot_clear_read_only() {
    let d = dev();
    set_fd(&d, Mem::with(alloc::vec![0; 4096], false), false).unwrap();
    set_status(&d, info(|i| i.lo_flags = 0)).unwrap();
    assert_eq!(get_status(&d).unwrap().lo_flags & LO_FLAGS_READ_ONLY, LO_FLAGS_READ_ONLY);
    // ...and it can set the flags it does own.
    set_status(&d, info(|i| i.lo_flags = LO_FLAGS_AUTOCLEAR | LO_FLAGS_PARTSCAN)).unwrap();
    let flags = get_status(&d).unwrap().lo_flags;
    assert_eq!(flags & (LO_FLAGS_AUTOCLEAR | LO_FLAGS_PARTSCAN), LO_FLAGS_AUTOCLEAR | LO_FLAGS_PARTSCAN);
}

/// `SET_CAPACITY` is what notices the backing file growing — the whole reason
/// the ioctl exists.
#[test]
fn set_capacity_notices_a_grown_file() {
    let d = dev();
    let mem = Mem::new(4096);
    set_fd(&d, mem.clone(), true).unwrap();
    mem.resize(16384);
    assert_eq!(d.capacity_blocks(), 8, "not until asked");
    assert_eq!(set_capacity(&d), Ok(32));
    assert_eq!(d.capacity_blocks(), 32);
}

/// An illegal block size is refused before it can be stored, so it can never
/// be read back.
#[test]
fn an_illegal_block_size_is_refused_and_not_stored() {
    let d = dev();
    set_fd(&d, Mem::new(4096), true).unwrap();
    for bad in [0u32, 100, 513, 8192] {
        assert_eq!(set_block_size(&d, bad), Err(Errno::Einval), "{bad}");
    }
    assert_eq!(d.status().unwrap().2, DEFAULT_BLOCK_SIZE, "unchanged");
    assert_eq!(set_block_size(&d, 4096), Ok(()));
    assert_eq!(d.status().unwrap().2, 4096);
}

/// Asking for direct I/O is refused rather than accepted-and-ignored: a
/// caller told its I/O bypasses a cache, when it does not, makes durability
/// decisions on a false premise.
#[test]
fn asking_for_direct_io_is_refused_not_silently_ignored() {
    let d = dev();
    set_fd(&d, Mem::new(4096), true).unwrap();
    assert_eq!(set_direct_io(&d, true), Err(Errno::Einval));
    assert_eq!(set_direct_io(&d, false), Ok(()), "asking for what is already true succeeds");
    assert_eq!(get_status(&d).unwrap().lo_flags & LO_FLAGS_DIRECT_IO, 0);
}

/// Binding a device that is already bound is refused, rather than swapping
/// the media under a mounted filesystem.
#[test]
fn binding_a_bound_device_is_refused() {
    let d = dev();
    set_fd(&d, Mem::new(4096), true).unwrap();
    assert_eq!(set_fd(&d, Mem::new(8192), true), Err(Errno::Ebusy));
    assert_eq!(d.capacity_blocks(), 8, "the first binding is untouched");
}

/// The name survives a round trip through the status ioctls, terminated.
#[test]
fn the_backing_name_round_trips_through_status() {
    let d = dev();
    let mut name = [0u8; LO_NAME_SIZE];
    name[..7].copy_from_slice(b"/img.gz");
    configure(&d, Mem::new(4096), true, info(|i| i.lo_file_name = name), 0).unwrap();
    assert_eq!(&get_status(&d).unwrap().lo_file_name[..7], b"/img.gz");
}
