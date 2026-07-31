//! Lane 1 (ext4-compat-plan): `SuperOps::sync_fs` MUST drain the cross-op
//! batched transaction. Linux `sync_filesystem` → `->sync_fs(wait)` is THE
//! per-superblock durability point; under batching the metadata sits in
//! `MountState.shadow` until `commit_batch`, so a `sync_fs` that called the
//! no-op `flush_pending_tx` returned success with metadata NOT on disk.

extern crate alloc;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;

fn fresh_disk() -> Arc<MemDisk<TaskList>> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest { op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: IMAGE.to_vec(), ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
    disk
}

/// begin_batch → create metadata via the VFS path → `sync_fs` → remount: the
/// created dir MUST be on disk. Before the fix `sync_fs` called the no-op
/// `flush_pending_tx`, leaving the mkdir only in the running shadow.
#[test]
fn syncfs_drains_batched_metadata() {
    let disk = fresh_disk();
    {
        let m = ext4::rootfs::Ext4Mount::open(disk.clone() as Arc<dyn BlockDevice>).unwrap();
        let st = m.state();
        st.mount.begin_batch(); // the boot's rootfs mode
        st.mkdir_at(b"/batchdir", 0o755).expect("mkdir /batchdir");
        // The durability drain under test: without it (old no-op flush_pending_tx)
        // the mkdir stays in MountState.shadow and the remount below can't see it.
        m.super_ops().expect("ext4 super_ops").sync_fs(true).expect("sync_fs drains the batch");
    }
    // Reopen the SAME backing store: the metadata must be durable on disk.
    let m2 = ext4::rootfs::Ext4Mount::open(disk as Arc<dyn BlockDevice>).unwrap();
    m2.state().lookup_path(b"/batchdir")
        .expect("batched /batchdir persisted across remount via sync_fs (Lane 1 fix)");
}
