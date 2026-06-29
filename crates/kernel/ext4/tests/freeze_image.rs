//! B235 coupling: ext4 `SuperOps::freeze_fs`/`thaw_fs` are wired (FIFREEZE/
//! FITHAW) — they flush+barrier the device and toggle the per-mount frozen
//! state, instead of inheriting the VFS no-op default.

extern crate alloc;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;

const IMAGE: &[u8] = include_bytes!("mini.img");
const SECTOR: u32 = 512;

fn build_disk() -> Arc<dyn BlockDevice> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32,
        buffer: IMAGE.to_vec(),
    };
    disk.submit_sync(&mut req).unwrap();
    disk
}

#[test]
fn freeze_then_thaw_toggles_frozen_state() {
    let m = ext4::rootfs::Ext4Mount::open(build_disk()).unwrap();
    let st = m.state().clone();
    let s_op = m.super_ops().expect("ext4 installs its own super_ops");

    assert!(!st.frozen.load(Ordering::Acquire), "starts thawed");

    s_op.sync_fs(true).expect("sync_fs flushes + barriers cleanly");

    s_op.freeze_fs().expect("freeze_fs returns Ok");
    assert!(st.frozen.load(Ordering::Acquire), "freeze_fs marks the mount frozen");

    s_op.thaw_fs().expect("thaw_fs returns Ok");
    assert!(!st.frozen.load(Ordering::Acquire), "thaw_fs clears frozen");
}
