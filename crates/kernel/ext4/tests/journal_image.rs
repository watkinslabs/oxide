//! P7b-06 integration: open a real journaled ext4 image, parse
//! its journal SB via Mount::recover_journal. Image is built
//! clean by mkfs.ext4, so replay is a no-op (s_start = 0); the
//! test verifies the parser can locate + decode the journal SB
//! through the journal inode's extents.

extern crate alloc;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;

const IMAGE: &[u8] = include_bytes!("mini-j.img");
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
fn journaled_image_mounts_clean() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    assert!(m.sb.has_extents());
    assert_ne!(m.sb.journal_inum, 0, "image has a journal inode (s_journal_inum)");
    // recover_journal() returns None for a clean log (INCOMPAT_RECOVER off).
    // Calling it must not error.
    let _ = m.recover_journal().unwrap();
}

#[test]
fn run_journaled_collects_metadata_writes_into_one_txn() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk.clone()).unwrap();
    let bs = m.sb.block_size as usize;
    let payload_a = std::vec![0xAA; bs];
    let payload_b = std::vec![0xBB; bs];
    m.run_journaled(|mm| {
        mm.metadata_write(120 * (bs as u64), &payload_a)?;
        mm.metadata_write(121 * (bs as u64), &payload_b)?;
        Ok(())
    }).unwrap();
    drop(m);
    for (lba, want) in [(120u64, &payload_a), (121u64, &payload_b)] {
        let mut req = block::BlockRequest::new_read(
            lba * (bs as u64) / 512, (bs / 512) as u32, 512,
        );
        disk.submit_sync(&mut req).unwrap();
        assert_eq!(&req.buffer[..bs], &want[..], "LBA {} matches", lba);
    }
}

#[test]
fn shadow_buffer_lets_subsequent_reads_see_staged_bytes() {
    // P7b-08: inside a run_journaled scope, a second metadata_write
    // to a block whose first write is still staged must see the
    // first write's bytes (so RMW within an op composes correctly).
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let bs = m.sb.block_size as usize;
    let lba = 130u64;
    m.run_journaled(|mm| {
        // Stage block: first half = 0xCC.
        let mut buf = std::vec![0u8; bs];
        for b in &mut buf[..bs/2] { *b = 0xCC; }
        mm.metadata_write(lba * (bs as u64), &buf)?;
        // Read back inside the scope — must see the staged bytes.
        let got = mm.read_meta_byte_range(lba * (bs as u64), bs)?;
        assert_eq!(got[0], 0xCC);
        assert_eq!(got[bs/2], 0);
        // RMW: overlay second half = 0xDD.
        let mut overlay = std::vec![0u8; bs/2];
        for b in &mut overlay { *b = 0xDD; }
        mm.metadata_write(lba * (bs as u64) + (bs as u64 / 2), &overlay)?;
        let got2 = mm.read_meta_byte_range(lba * (bs as u64), bs)?;
        assert_eq!(got2[0],     0xCC, "first half preserved across RMW");
        assert_eq!(got2[bs/2],  0xDD, "second half overlaid");
        Ok(())
    }).unwrap();
}

#[test]
fn create_file_inside_scope_atomically() {
    // Wrap an entire create_file in run_journaled — the alloc_inode
    // (modifies inode bitmap + GDT + SB), init_inode (writes new
    // inode bytes), and dir_link (writes parent's dir block) all
    // share the same shadow + commit as one transaction.
    let disk = build_disk();
    let m = ext4::Mount::open(disk.clone()).unwrap();
    let n = m.run_journaled(|mm| mm.create_file(2, b"atomic", 0o644)).unwrap();
    assert!(n > 0);
    // Re-open: file is visible (transaction committed).
    drop(m);
    let m2 = ext4::Mount::open(disk).unwrap();
    let got = m2.lookup_path(b"/atomic").unwrap();
    assert_eq!(got, n);
}

#[test]
fn commit_metadata_routes_through_journal() {
    // Build a small staged transaction and round-trip through
    // Mount::commit_metadata. The same bytes must land at the
    // target LBA, and (since we're simulating commit) the journal
    // SB s_start should return to 0.
    let disk = build_disk();
    let m = ext4::Mount::open(disk.clone()).unwrap();
    let bs = m.sb.block_size as usize;
    // Pick a non-critical fs block (block 100 — well past the
    // GDT/bitmaps/inode-tables for this layout).
    let target_lba = 100u64;
    let payload = std::vec![0xFA; bs];
    let staged = std::vec![ext4::StagedBlock { target_lba, data: payload.clone() }];
    let seq = m.commit_metadata(staged).unwrap();
    let _ = seq;  // any non-error sequence is fine
    // Re-open + read block 100 directly via a 1-block BlockRequest.
    drop(m);
    let mut req = block::BlockRequest::new_read(target_lba * (bs as u64) / 512, (bs / 512) as u32, 512);
    disk.submit_sync(&mut req).unwrap();
    let mut out = std::vec::Vec::new();
    out.extend_from_slice(&req.buffer[..bs]);
    assert_eq!(out, payload, "committed block landed at target LBA");
}

#[test]
fn journaled_image_supports_writes() {
    // Even with a journal present + recover support running, the
    // ext4 RW path (alloc_block + create_file + …) must continue
    // to work. Replay is no-op, then we exercise the live writes.
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"jt.bin", 0o644).unwrap();
    let bs = m.sb.block_size as usize;
    m.append_block(n, &std::vec![0xEE; bs]).unwrap();
    let inode = m.read_inode(n).unwrap();
    assert_eq!(inode.size, bs as u64);
    let blk = m.read_file_block(&inode, 0).unwrap();
    assert_eq!(blk, std::vec![0xEE; bs]);
}
