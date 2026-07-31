//! Lane 2 (ext4-compat-plan): a batched mount dropped WITHOUT an explicit sync
//! must still persist its session metadata and a durable clean bit. Linux
//! `put_super` writes back before the final clean mark; our `Ext4Mount::Drop`
//! now commits the running batch, reaps orphans, marks clean, and commits again
//! so nothing staged in `MountState.shadow` is lost when the mount tears down.

extern crate alloc;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;

fn fresh_disk() -> Arc<MemDisk<TaskList>> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest { op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: IMAGE.to_vec(), ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
    disk
}

#[test]
fn batched_mutation_survives_drop_without_explicit_sync() {
    let disk = fresh_disk();
    let child = {
        let m = ext4::rootfs::Ext4Mount::open(disk.clone() as Arc<dyn BlockDevice>).unwrap();
        m.state().mount.begin_batch();
        // Session metadata staged into the running batch; NO sync_fs / commit_batch.
        let d = m.state().mount.create_dir(2, b"survivor", 0o755, 0, 0).expect("mkdir survivor");
        let c = m.state().mount.create_dir(d, b"leaf", 0o755, 0, 0).expect("mkdir leaf");
        c
        // `m` drops here — Drop must drain the batch.
    };
    // Reopen: the batched-but-never-explicitly-synced tree must be on disk.
    let m2 = ext4::rootfs::Ext4Mount::open(disk as Arc<dyn BlockDevice>).unwrap();
    let got = m2.state().mount.lookup_path(b"/survivor/leaf")
        .expect("batched metadata persisted across Drop (Lane 2 fix)");
    assert_eq!(got, child, "same inode after remount");
}
