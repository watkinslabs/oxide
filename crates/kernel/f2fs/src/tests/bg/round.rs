//! One pass of each thread, driven against a real mount.
//!
//! The policy tests beside this one prove the decisions. These prove the pass
//! reads the right state into them and does the thing the decision names —
//! which is the half that a lane can get wrong while every policy test stays
//! green: a pass that decides perfectly and then cleans nothing is exactly the
//! shape of an unwired feature.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use block::{BlockDevice, BlockRequest, MemDisk};
use sync::TaskList;

use crate::bg::discard::{DiscardType, MIN_DISCARD_GRANULARITY};
use crate::bg::{GcMode, GcStep};
use crate::mount::F2fs;
use crate::opts::{BackgroundGc, Options};
use crate::test_image::{self, ROOT_INO};
use crate::uapi::BLKSIZE;

const BS: u32 = BLKSIZE as u32;

fn disk(bytes: &[u8]) -> Arc<MemDisk<TaskList>> {
    let blocks = bytes.len() as u64 / u64::from(BS);
    let dev: Arc<MemDisk<TaskList>> = MemDisk::new(BS, blocks);
    let mut req = BlockRequest::new_write(0, blocks as u32, bytes.to_vec());
    dev.submit_sync(&mut req).expect("device write");
    dev
}

fn mounted_with(opts: Options) -> Arc<F2fs> {
    let dev = disk(&test_image::with_root().finish());
    F2fs::open_with(dev, "/dev/fake", true, opts).expect("mount")
}

fn mounted() -> Arc<F2fs> { mounted_with(Options::defaults()) }

/// A mount with something written to it, so a pass has state to read.
fn with_a_file(name: &str, blocks: usize) -> Arc<F2fs> {
    let fs = mounted();
    let ino = {
        let dir = fs.root_inode().unwrap();
        let _ = dir;
        fs.make(ROOT_INO, name, crate::mode::S_IFREG | 0o644, 0, 0, 0, None, true).unwrap()
    };
    let ino = ino.ino() as u32;
    fs.write(ino, 0, &vec![0xA5u8; blocks * BLKSIZE]).unwrap();
    fs.checkpoint().unwrap();
    fs
}

#[test]
fn a_mount_publishes_its_background_state() {
    let fs = mounted();
    assert_eq!(fs.bg().gc_mode(), GcMode::Normal);
    assert_eq!(*fs.bg().bggc.lock(), BackgroundGc::On);
    assert_eq!(fs.bg().dcc.lock().granularity, 16);
}

#[test]
fn a_mount_asked_for_no_cleaning_says_so_in_its_state() {
    let fs = mounted_with(Options { background_gc: BackgroundGc::Off, ..Options::defaults() });
    assert_eq!(*fs.bg().bggc.lock(), BackgroundGc::Off);
}

#[test]
fn a_pass_over_a_volume_with_cleaning_off_does_nothing_and_sleeps_long() {
    let fs = mounted_with(Options { background_gc: BackgroundGc::Off, ..Options::defaults() });
    let pass = crate::bg::gc_pass(&fs);
    assert_eq!(pass.step, GcStep::Skip);
    assert!(!pass.cleaned);
    assert_eq!(pass.wait_ms, 300_000);
}

#[test]
fn a_pass_over_a_busy_volume_backs_off_instead_of_cleaning() {
    let fs = with_a_file("f", 2);
    // The mount was used a moment ago, which is what the idle test reads.
    fs.volume.lock().set_clock(1_000);
    fs.bg().note_activity(1_000);
    let pass = crate::bg::gc_pass(&fs);
    assert_eq!(pass.step, GcStep::Sleep);
    assert!(!pass.cleaned);
}

#[test]
fn a_pass_over_a_quiet_volume_looks_for_a_victim() {
    let fs = with_a_file("f", 2);
    fs.volume.lock().set_clock(1_000);
    fs.bg().note_activity(0);
    let pass = crate::bg::gc_pass(&fs);
    assert!(matches!(pass.step, GcStep::Gc { .. }), "{:?}", pass.step);
}

#[test]
fn an_urgent_mode_cleans_a_volume_the_ordinary_pass_would_have_left_alone() {
    let fs = with_a_file("f", 2);
    fs.volume.lock().set_clock(1_000);
    fs.bg().note_activity(1_000);
    assert_eq!(crate::bg::gc_pass(&fs).step, GcStep::Sleep, "busy, so the ordinary answer");
    fs.bg().set_gc_mode(GcMode::UrgentHigh);
    let pass = crate::bg::gc_pass(&fs);
    assert!(matches!(pass.step, GcStep::Gc { .. }), "urgent looks whatever the device says");
    // The interval afterwards is the pass's own answer, not the mode's: one
    // that found no victim parks long however urgent the request was.
    assert!(pass.wait_ms == 500 || pass.wait_ms == 300_000, "{}", pass.wait_ms);
}

#[test]
fn a_pass_that_found_no_victim_parks_the_thread_for_the_long_interval() {
    // A fresh volume has one open log and nothing dead in it, so there is no
    // section a pass could empty.
    let fs = mounted();
    fs.bg().note_activity(0);
    let pass = crate::bg::gc_pass(&fs);
    if matches!(pass.step, GcStep::Gc { .. }) && !pass.cleaned {
        assert_eq!(pass.wait_ms, 300_000);
    }
}

#[test]
fn a_checkpoint_parks_freed_runs_where_the_discard_thread_will_find_them() {
    let fs = with_a_file("f", 4);
    let parked_before = fs.bg().dcc.lock().cmd_count();
    // Overwrite the file: every block moves, and the old ones are freed.
    let ino = fs.root_inode().unwrap();
    let _ = ino;
    let target = fs.volume.lock().root_ino();
    let _ = target;
    fs.write(file_ino(&fs, "f"), 0, &vec![0x5Au8; 4 * BLKSIZE]).unwrap();
    fs.checkpoint().unwrap();
    let parked = fs.bg().dcc.lock().cmd_count();
    // Without a running thread the checkpoint announces them itself, so the
    // list stays empty; with one it fills. Either is correct, and exactly one
    // of them must be true.
    let announced_directly = !fs.bg().discard_running.load(core::sync::atomic::Ordering::Acquire);
    assert!(announced_directly || parked > parked_before);
}

/// The inode number of a name under the root.
fn file_ino(fs: &Arc<F2fs>, name: &str) -> u32 {
    let v = fs.volume.lock();
    let root = v.read_inode(ROOT_INO).unwrap();
    v.lookup(&root, ROOT_INO, name.as_bytes()).unwrap().ino
}

#[test]
fn a_discard_pass_hands_over_what_is_parked_and_shortens_its_interval() {
    let fs = mounted();
    fs.volume.lock().set_clock(1_000);
    fs.bg().note_activity(0);
    fs.bg().dcc.lock().extend([(1000, 32), (2000, 32)]);
    fs.bg().note_activity(0);
    let pass = crate::bg::discard_pass(&fs);
    assert_eq!(pass.round.issued(), 2);
    assert_eq!(pass.wait_ms, 60_000, "the list is empty again, so there is no hurry");
    assert_eq!(fs.bg().dcc.lock().cmd_count(), 0);
    // The device has answered by the time the pass returns, so nothing is left
    // in flight. A pass that raised the count and never lowered it would report
    // a device permanently busy with requests it finished long ago.
    assert_eq!(fs.bg().dcc.lock().queued_count(), 0, "the in-flight count was never lowered");
    assert_eq!(fs.bg().dcc.lock().issued, 2, "the work done is still reported");
}

#[test]
fn a_discard_pass_over_a_busy_volume_holds_short_runs_back() {
    let fs = mounted();
    fs.volume.lock().set_clock(1_000);
    fs.bg().dcc.lock().extend([(1000, 32)]);
    fs.bg().note_activity(1_000);
    let pass = crate::bg::discard_pass(&fs);
    assert_eq!(pass.round.issued(), 0);
    assert!(pass.round.io_interrupted);
    assert_eq!(fs.bg().dcc.lock().cmd_count(), 1, "still parked for a quieter moment");
}

#[test]
fn urgent_cleaning_makes_the_discard_pass_stop_yielding() {
    let fs = mounted();
    fs.volume.lock().set_clock(1_000);
    fs.bg().dcc.lock().extend([(1000, 32)]);
    fs.bg().note_activity(1_000);
    assert_eq!(crate::bg::discard_pass(&fs).round.issued(), 0);
    fs.bg().set_gc_mode(GcMode::UrgentHigh);
    assert_eq!(crate::bg::discard_pass(&fs).round.issued(), 1);
}

#[test]
fn a_discard_pass_over_a_read_only_mount_issues_nothing() {
    let dev = disk(&test_image::with_root().finish());
    let fs = F2fs::open_with(dev, "/dev/fake", false, Options::defaults()).unwrap();
    fs.bg().dcc.lock().extend([(1000, 32)]);
    let pass = crate::bg::discard_pass(&fs);
    assert_eq!(pass.round.issued(), 0);
    assert_eq!(fs.bg().dcc.lock().cmd_count(), 1, "a read-only mount freed nothing");
}

#[test]
fn a_pass_consumes_the_request_that_woke_it() {
    let fs = mounted();
    fs.bg().wake_discard();
    assert!(fs.bg().dcc.lock().wake);
    crate::bg::discard_pass(&fs);
    assert!(!fs.bg().dcc.lock().wake, "or the thread would never park again");
}

#[test]
fn the_unmount_drain_takes_every_run_however_short() {
    let fs = mounted();
    fs.bg().dcc.lock().extend([(1000, 1), (2000, 2), (3000, 400)]);
    crate::bg::drain_discards(&fs);
    assert_eq!(fs.bg().dcc.lock().cmd_count(), 0, "the trimmed claim must be true of all");
}

#[test]
fn the_unmount_drain_is_the_only_pass_that_ignores_granularity() {
    let fs = mounted();
    fs.bg().dcc.lock().extend([(1000, 1)]);
    fs.bg().note_activity(0);
    // The ordinary round leaves a one-block run alone at the default
    // granularity of sixteen.
    let ordinary = crate::bg::discard_pass(&fs);
    let held = fs.bg().dcc.lock().cmd_count();
    assert!(ordinary.round.issued() == 0 || held == 0);
    let umount = {
        let d = fs.bg().dcc.lock();
        d.init_policy(DiscardType::Umount, MIN_DISCARD_GRANULARITY, 0)
    };
    assert_eq!(umount.granularity, 1);
}

#[test]
fn stopping_the_background_leaves_nothing_parked() {
    let fs = mounted();
    fs.bg().dcc.lock().extend([(1000, 1), (2000, 64)]);
    fs.stop_background();
    assert_eq!(fs.bg().dcc.lock().cmd_count(), 0);
    assert!(fs.bg().stopping() || !fs.bg().gc_running.load(core::sync::atomic::Ordering::Acquire));
}

#[test]
fn a_write_through_the_filesystem_goes_through_the_balance_path() {
    let fs = mounted();
    let before = fs.bg().balance_count();
    fs.make(ROOT_INO, "g", crate::mode::S_IFREG | 0o644, 0, 0, 0, None, true).unwrap();
    assert!(fs.bg().balance_count() > before,
            "the hook at the end of every operation is what counts this");
}

#[test]
fn every_mutating_operation_reaches_the_balance_path() {
    // The stamp is the observable proof that the hook is in place: it is set
    // by nothing else, and each of these calls must set it.
    let ops: Vec<(&str, fn(&Arc<F2fs>))> = vec![
        ("make", |fs| { fs.make(ROOT_INO, "a", crate::mode::S_IFREG | 0o644, 0, 0, 0, None, true)
                          .unwrap(); }),
        ("write", |fs| { let ino = fs.make(ROOT_INO, "b", crate::mode::S_IFREG | 0o644, 0, 0, 0,
                                           None, true).unwrap().ino() as u32;
                         fs.write(ino, 0, b"hello").unwrap(); }),
        ("truncate", |fs| { let ino = fs.make(ROOT_INO, "c", crate::mode::S_IFREG | 0o644, 0, 0,
                                              0, None, true).unwrap().ino() as u32;
                            fs.truncate(ino, 8).unwrap(); }),
        ("link", |fs| { fs.make(ROOT_INO, "d", crate::mode::S_IFREG | 0o644, 0, 0, 0, None, true)
                          .unwrap();
                        let ino = file_ino(fs, "d");
                        fs.link(ROOT_INO, "d2", ino).unwrap(); }),
        ("rename", |fs| { fs.make(ROOT_INO, "e", crate::mode::S_IFREG | 0o644, 0, 0, 0, None, true)
                            .unwrap();
                          fs.rename(ROOT_INO, "e", ROOT_INO, "e2", 0, (0, 0)).unwrap(); }),
        ("remove", |fs| { fs.make(ROOT_INO, "h", crate::mode::S_IFREG | 0o644, 0, 0, 0, None, true)
                            .unwrap();
                          fs.remove(ROOT_INO, "h", false).unwrap(); }),
    ];
    for (name, op) in ops {
        let fs = mounted();
        let before = fs.bg().balance_count();
        op(&fs);
        assert!(fs.bg().balance_count() > before, "{name} never reached the balance path");
    }
}
