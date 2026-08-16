// Publishing and withdrawal, driven against a real mount.
//
// The global hooks these tests install are process-wide and other tests in
// this crate mount filesystems of their own concurrently, so every assertion
// below is about ONE named mount rather than about a count of calls.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;

use super::*;
use crate::rootfs::Ext4Mount;

const IMAGE: &[u8] = include_bytes!("../../tests/mini-j.img");
const SECTOR: u32 = 512;

fn fresh_dev() -> Arc<dyn BlockDevice> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let inner: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32,
        buffer: Vec::from(IMAGE), ..Default::default()
    };
    inner.submit_sync(&mut req).unwrap();
    inner
}

/// The one mount the publisher below is watching for.
static WATCHED: AtomicUsize = AtomicUsize::new(0);
static SEEN: AtomicU32 = AtomicU32::new(0);
static WITHDRAWN: AtomicU32 = AtomicU32::new(0);

fn watch_publish(st: &Arc<RootfsState>) {
    if Arc::as_ptr(st) as usize == WATCHED.load(Ordering::Relaxed) {
        SEEN.fetch_add(1, Ordering::Relaxed);
    }
}

fn watch_withdraw(dev: &str) {
    if dev == "a-name-no-disk-has" { WITHDRAWN.fetch_add(1, Ordering::Relaxed); }
}

/// One test, three assertions, because the hooks are process-wide: installing
/// a publisher is a one-way step for the whole test binary, so the
/// before-install case cannot be a separate test that might run second.
///
/// Before install: the root filesystem is mounted while the machine is coming
/// up, and the registrations that install the publisher run afterwards. A
/// build that only published mounts arriving later would leave the one
/// filesystem every system has with no reports at all.
///
/// After install: a mount is published as it comes up rather than waiting for
/// something to drain it.
///
/// And unmount withdraws what mount published, or a directory reporting on a
/// volume nobody can reach outlives it.
#[test]
fn mounts_are_published_whichever_side_of_the_install_they_arrive_on() {
    let early = Ext4Mount::open_with_data(fresh_dev(), None, "").expect("mounts");
    let early_st = early.state().clone();
    // `open` already announced it; with no publisher installed, that
    // announcement is the remembered one.
    WATCHED.store(Arc::as_ptr(&early_st) as usize, Ordering::Relaxed);
    SEEN.store(0, Ordering::Relaxed);
    set_publisher(watch_publish);
    assert_eq!(SEEN.load(Ordering::Relaxed), 1, "the remembered mount was published");

    let late = Ext4Mount::open_with_data(fresh_dev(), None, "").expect("mounts");
    let late_st = late.state().clone();
    WATCHED.store(Arc::as_ptr(&late_st) as usize, Ordering::Relaxed);
    SEEN.store(0, Ordering::Relaxed);
    note_mounted(&late_st);
    assert_eq!(SEEN.load(Ordering::Relaxed), 1, "a later mount publishes at once");

    set_withdraw(watch_withdraw);
    WITHDRAWN.store(0, Ordering::Relaxed);
    run_withdraw("a-name-no-disk-has");
    run_withdraw("some-other-name");
    assert_eq!(WITHDRAWN.load(Ordering::Relaxed), 1, "one mount's name, not another's");
}

/// A mount on a registered disk publishes under that disk's name — the same
/// name this kernel already answers when a program asks which sysfs directory
/// describes its filesystem. A different name here would make that answer a
/// path that does not exist.
#[test]
fn a_registered_mount_publishes_under_its_disks_name() {
    let (st, name) = registered_mount("vdsurf1");
    assert_eq!(crate::sysfs::mount_dir(&st).as_deref(), Some(name.as_str()));
    let names: Vec<&'static str> = crate::sysfs::mount_attrs(&st).iter().map(|a| a.name).collect();
    for expected in ["session_write_kbytes", "lifetime_write_kbytes", "errors_count",
                     "first_error_time", "first_error_ino", "first_error_block",
                     "first_error_errcode", "last_error_time", "last_error_ino",
                     "last_error_block", "last_error_errcode"] {
        assert!(names.contains(&expected), "{expected} is not published");
    }
    for a in crate::sysfs::mount_attrs(&st) {
        assert_eq!(a.dir, name, "every report lives in the mount's own directory");
    }
}

/// A mount that is not on a registered disk has no name to publish under, and
/// publishes nothing rather than inventing one.
#[test]
fn an_unregistered_mount_publishes_nothing() {
    let m = Ext4Mount::open_with_data(fresh_dev(), None, "").expect("mounts");
    let st = m.state().clone();
    assert_eq!(crate::sysfs::mount_dir(&st), None);
    assert!(crate::sysfs::mount_attrs(&st).is_empty());
}

/// The session report is the writing done SINCE this mount began, so it must
/// move when the device is written and start from what the mount inherited.
#[test]
fn the_session_report_follows_the_writing_done() {
    let (st, name) = registered_mount("vdsurf2");
    let attrs = crate::sysfs::mount_attrs(&st);
    let session = attrs.iter().find(|a| a.name == "session_write_kbytes").expect("published");
    let lifetime = attrs.iter().find(|a| a.name == "lifetime_write_kbytes").expect("published");
    let before = read_u64(&(session.show)().unwrap());
    let life_before = read_u64(&(lifetime.show)().unwrap());
    assert_eq!(life_before, st.mount.sb.kbytes_written + before);

    // Eight 512-byte sectors through the registered disk: four kilobytes.
    let disk = block::registry::by_name(&name).expect("registered");
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: 8,
        buffer: alloc::vec![0u8; 8 * SECTOR as usize], ..Default::default()
    };
    disk.dev.submit_sync(&mut req).expect("write");

    let after = read_u64(&(session.show)().unwrap());
    assert_eq!(after, before + 4, "four kilobytes of writing is four kilobytes reported");
    assert_eq!(read_u64(&(lifetime.show)().unwrap()), st.mount.sb.kbytes_written + after,
               "the lifetime report is the volume's own count plus this session's");
}

/// The reports answer from the live record, so an error found after they were
/// published is visible through them. Without the recording call in the one
/// place errors are reported from, every one of these stays at what the
/// superblock carried.
#[test]
fn a_reported_error_reaches_the_reports() {
    let (st, _) = registered_mount("vdsurf3");
    let attrs = crate::sysfs::mount_attrs(&st);
    let count = attrs.iter().find(|a| a.name == "errors_count").expect("published");
    let last_code = attrs.iter().find(|a| a.name == "last_error_errcode").expect("published");
    let first_code = attrs.iter().find(|a| a.name == "first_error_errcode").expect("published");
    let before = read_u64(&(count.show)().unwrap());

    let mapped = crate::rootfs::fserror::report(&st, crate::MountError::BadChecksum);
    assert_eq!(mapped, vfs::VfsError::Eio, "a corruption is still refused to the caller");

    assert_eq!(read_u64(&(count.show)().unwrap()), before + 1);
    assert_eq!(read_u64(&(last_code.show)().unwrap()) as u8, crate::errstat::code::EFSBADCRC);
    assert_eq!(read_u64(&(first_code.show)().unwrap()) as u8, crate::errstat::code::EFSBADCRC,
               "the first event on a clean volume is this one");

    // An answer about a healthy filesystem is not a filesystem error and must
    // not appear in the history a monitoring daemon is watching.
    let _ = crate::rootfs::fserror::report(&st, crate::MountError::NotFound);
    assert_eq!(read_u64(&(count.show)().unwrap()), before + 1, "only real errors are counted");
}

/// A mount over a freshly registered disk, and the name it was registered as.
fn registered_mount(name: &str) -> (Arc<RootfsState>, alloc::string::String) {
    let idx = block::registry::register(name, fresh_dev());
    assert!(idx != 0, "registered");
    let disk = block::registry::by_name(name).expect("registered");
    // The mount must hold the registry's OWN device object: that identity is
    // what ties a mount to its disk, and it is what every real mount path
    // hands over.
    let m = Ext4Mount::open_with_data(disk.dev.clone(), None, "errors=continue").expect("mounts");
    (m.state().clone(), alloc::string::String::from(name))
}

fn read_u64(bytes: &[u8]) -> u64 {
    let s = core::str::from_utf8(bytes).expect("utf8");
    s.trim_end().parse().expect("a decimal line")
}
