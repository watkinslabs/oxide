//! Reconfiguring a live mount: what the line reaches, and what a refused line
//! leaves behind.

use super::*;
use crate::opts::{BackgroundGc, DiscardUnit, Options};
use crate::test_image;
use crate::uapi::BLKSIZE;
use alloc::sync::Arc;
use block::{BlockDevice, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::superblock::SB_RDONLY;
use vfs::fs::FileSystem;

const BS: u32 = BLKSIZE as u32;

/// A writable filesystem over a fresh fixture image.
fn mounted() -> Arc<F2fs> {
    let bytes = test_image::with_root().finish();
    let blocks = bytes.len() as u64 / u64::from(BS);
    let dev: Arc<MemDisk<TaskList>> = MemDisk::new(BS, blocks);
    let mut req = BlockRequest::new_write(0, blocks as u32, bytes);
    dev.submit_sync(&mut req).expect("device write");
    F2fs::open_line(dev, "/dev/fake", true, "").expect("mount")
}

// -------------------------------------------------- the line reaches the mount

#[test]
fn background_gc_off_reaches_the_options_and_the_threads_knob() {
    // The knob is what the cleaner reads every round. A remount that changed
    // the option and not the knob would report `background_gc=off` in the
    // mount table while the thread carried on cleaning.
    let fs = mounted();
    assert_eq!(fs.options().background_gc, BackgroundGc::On);
    assert_eq!(*fs.bg().bggc.lock(), BackgroundGc::On);
    fs.remount("background_gc=off", false).expect("remount");
    assert_eq!(fs.options().background_gc, BackgroundGc::Off);
    assert_eq!(*fs.bg().bggc.lock(), BackgroundGc::Off, "the knob followed the option");
}

#[test]
fn the_cleaner_can_be_turned_back_on() {
    let fs = mounted();
    fs.remount("background_gc=off", false).expect("off");
    fs.remount("background_gc=sync", false).expect("on");
    assert_eq!(*fs.bg().bggc.lock(), BackgroundGc::Sync);
}

#[test]
fn an_option_the_new_line_stops_naming_goes_back_to_its_default() {
    let fs = mounted();
    fs.remount("background_gc=off,noinline_data", false).expect("remount");
    assert!(!fs.options().inline_data);
    fs.remount("", false).expect("remount");
    assert_eq!(fs.options().background_gc, BackgroundGc::On);
    assert!(fs.options().inline_data);
}

#[test]
fn the_mount_table_shows_what_the_remount_settled_on() {
    let fs = mounted();
    fs.remount("background_gc=off,noacl", false).expect("remount");
    let shown = FileSystem::show_options(&*fs);
    assert!(shown.contains(",background_gc=off"), "{shown}");
    assert!(shown.contains(",noacl"), "{shown}");
}

// ------------------------------------------------------------- writability

#[test]
fn a_remount_read_only_stops_the_writes_and_the_threads() {
    let fs = mounted();
    assert!(fs.is_writable());
    fs.remount("", true).expect("remount ro");
    assert!(!fs.is_writable());
    assert!(fs.bg().stopping(), "the threads were wound up");
}

#[test]
fn coming_back_read_write_lets_the_threads_run_again() {
    // The stop flag is how an unmount winds the threads up; leaving it raised
    // would give a writable mount no cleaner and nothing saying so.
    let fs = mounted();
    fs.remount("", true).expect("remount ro");
    assert!(fs.bg().stopping());
    fs.remount("", false).expect("remount rw");
    assert!(fs.is_writable());
    assert!(!fs.bg().stopping());
}

#[test]
fn the_super_operation_carries_the_line_through() {
    // The one that matters: `mount -o remount,...` arrives here, and a
    // filesystem that ignored `data` would honour the option nowhere.
    let fs = mounted();
    let ops = FileSystem::super_ops(&*fs).expect("super ops");
    ops.remount_fs(0, "background_gc=off").expect("remount");
    assert_eq!(fs.options().background_gc, BackgroundGc::Off);
    ops.remount_fs(SB_RDONLY, "").expect("remount ro");
    assert!(!fs.is_writable());
}

// ---------------------------------------------------------- a refused line

#[test]
fn a_refused_line_leaves_the_mount_exactly_as_it_was() {
    let fs = mounted();
    let before = fs.options();
    // Switching the extent cache is not allowed while mounted.
    assert!(fs.remount("noextent_cache,background_gc=off", false).is_err());
    assert_eq!(fs.options(), before, "nothing was applied");
    assert_eq!(*fs.bg().bggc.lock(), BackgroundGc::On, "and the threads did not move");
    assert!(fs.is_writable());
}

#[test]
fn a_line_that_does_not_parse_is_refused_without_changing_anything() {
    let fs = mounted();
    let before = fs.options();
    assert!(fs.remount("background_gc=sideways", false).is_err());
    assert_eq!(fs.options(), before);
}

#[test]
fn the_discard_unit_may_not_be_switched_under_a_running_mount() {
    let fs = mounted();
    assert_eq!(fs.options().discard_unit, DiscardUnit::Block);
    assert!(fs.remount("discard_unit=section", false).is_err());
    assert_eq!(fs.options().discard_unit, DiscardUnit::Block);
}

// ------------------------------------------------------ defaults at mount

#[test]
fn a_line_mount_derives_its_defaults_from_the_volume() {
    // The fixture is small and its device cannot discard, so both of those
    // defaults must come out the volume's way rather than the build's.
    let fs = mounted();
    let o = fs.options();
    assert!(!o.discard, "a device that cannot discard is not told to");
    assert_eq!(o.active_logs, 6, "the volume is not marked read-only");
    assert!(o.flush_merge, "a writable mount merges");
    let segs = fs.volume.lock().super_block().segment_count_main;
    let want = if segs <= crate::opts::facts::SMALL_VOLUME_SEGMENTS {
        crate::opts::AllocMode::Reuse
    } else {
        crate::opts::AllocMode::Default
    };
    assert_eq!(o.alloc_mode, want, "{segs} main segments");
    assert_ne!(o, Options::defaults(), "the derived set is not the build-wide one");
}
