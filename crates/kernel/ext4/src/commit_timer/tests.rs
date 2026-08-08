// The periodic commit driven end-to-end against a real image: a mount that has
// staged metadata into its running transaction and has not been told to sync
// still reaches the disk, because its `commit=` interval elapsed.

use alloc::sync::Arc;
use alloc::vec::Vec;
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

/// Mounting registers the mount, and the FIRST tick only starts its clock —
/// the age of a transaction nobody has timed yet is not "infinite".
#[test]
fn the_first_tick_starts_the_interval_rather_than_committing() {
    let m = Ext4Mount::open_with_data(fresh_dev(), None, "commit=5").expect("mounts");
    let mount = m.state().mount.clone();
    tick(0);
    let seen = MOUNTS.lock().iter()
        .find(|r| Weak::as_ptr(&r.mount) == Arc::as_ptr(&mount))
        .map(|r| r.last_ns);
    assert_eq!(seen, Some(Some(0)), "the mount is registered and its clock started");
}

/// The interval a mount NAMED is the interval it gets: a tick one second in
/// leaves a `commit=30` mount alone and a `commit=1` mount due.
#[test]
fn the_named_interval_decides_when_a_mount_is_due() {
    let slow = Ext4Mount::open_with_data(fresh_dev(), None, "commit=30").expect("mounts");
    let fast = Ext4Mount::open_with_data(fresh_dev(), None, "commit=1").expect("mounts");
    assert_eq!(slow.state().opts().behaviour.commit_secs, 30);
    assert_eq!(fast.state().opts().behaviour.commit_secs, 1);

    let base = 1_000_000_000_000u64;
    tick(base);
    tick(base + due::NS_PER_SEC);

    let g = MOUNTS.lock();
    let last_of = |m: &Arc<crate::Mount>| g.iter()
        .find(|r| Weak::as_ptr(&r.mount) == Arc::as_ptr(m))
        .and_then(|r| r.last_ns);
    assert_eq!(last_of(&slow.state().mount), Some(base),
        "commit=30 is not due one second in");
    assert_eq!(last_of(&fast.state().mount), Some(base + due::NS_PER_SEC),
        "commit=1 is");
}

/// A dropped mount does not keep its registration — the timer holds a weak
/// reference, and the walk that finds a dead one prunes it.
#[test]
fn an_unmounted_filesystem_leaves_no_registration_behind() {
    let mount = {
        let m = Ext4Mount::open_with_data(fresh_dev(), None, "commit=5").expect("mounts");
        Arc::downgrade(&m.state().mount)
    };
    tick(0);
    assert!(!MOUNTS.lock().iter().any(|r| Weak::as_ptr(&r.mount) == Weak::as_ptr(&mount)),
        "the registration went with the mount");
}

/// A tick timestamp nobody else will reuse, and that always moves forward.
/// The registry is global and these tests run in parallel, so a shared,
/// monotonically increasing clock is what keeps one test's tick from looking
/// like a backwards jump to another's mount.
fn tick_now() -> u64 {
    use core::sync::atomic::{AtomicU64, Ordering};
    static CLOCK: AtomicU64 = AtomicU64::new(1_000_000_000_000);
    CLOCK.fetch_add(due::NS_PER_SEC, Ordering::AcqRel)
}

/// The periodic walk is what DRIVES lazy inode-table initialisation: a mount
/// that named the option gets a group done without anybody asking.
#[test]
fn the_periodic_walk_initialises_an_inode_table() {
    let m = Ext4Mount::open_with_data(fresh_dev(), None, "init_itable=10").expect("mounts");
    let mount = m.state().mount.clone();
    let (off, len) = crate::itable_init::tests::dirty_the_table(&mount, 0);

    run_itable_init(tick_now());
    let after = crate::mount::read_byte_range_pub(&*mount.dev, off, len).unwrap();
    assert!(after.iter().all(|b| *b == 0), "the walk zeroed the never-used table");
}

/// `noinit_itable` is honoured by the walk, not merely stored: the same image
/// under the same tick is left exactly as it was.
#[test]
fn the_periodic_walk_leaves_a_mount_that_refused_the_job_alone() {
    let m = Ext4Mount::open_with_data(fresh_dev(), None, "noinit_itable").expect("mounts");
    let mount = m.state().mount.clone();
    let (off, len) = crate::itable_init::tests::dirty_the_table(&mount, 0);

    run_itable_init(tick_now());
    let after = crate::mount::read_byte_range_pub(&*mount.dev, off, len).unwrap();
    assert!(after.iter().any(|b| *b != 0), "a mount that refused the job was initialised anyway");
}

/// A mount pauses between groups by the multiple its option names, so the job
/// never becomes a device-wide stall. The pause is priced by the tick that
/// observes the group finished, which is why two ticks are needed to see it.
#[test]
fn a_mount_waits_out_the_pause_its_option_earned() {
    const MULT: u64 = 10;
    let m = Ext4Mount::open_with_data(fresh_dev(), None, "init_itable=10").expect("mounts");
    let mount = m.state().mount.clone();
    crate::itable_init::tests::dirty_the_table(&mount, 0);
    let first = tick_now();

    run_itable_init(first);
    run_itable_init(tick_now());
    let g = MOUNTS.lock();
    let mine = g.iter().find(|r| Weak::as_ptr(&r.mount) == Arc::as_ptr(&mount)).expect("registered");
    assert_eq!(mine.itable.last_ns, Some(first), "the pause is timed from the group it paid for");
    assert!(mine.itable.wait_ns >= MULT * due::NS_PER_SEC,
        "the pause is the measured work times the multiplier; saw {}", mine.itable.wait_ns);
}
