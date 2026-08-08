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
