//! B1482: `i_blocks` counts blocks ACTUALLY allocated to the inode, never a
//! prediction. Linux charges at allocation time — `ext4_mb_new_blocks`
//! (fs/ext4/mballoc.c) calls `dquot_alloc_block` before handing out the block,
//! and `__dquot_alloc_space` (fs/quota/dquot.c) is what runs `inode_add_bytes`
//! — so the data block and each extent-tree metadata block are charged once
//! each, when they are really taken.
//!
//! The append path used to precharge a metadata block whenever the leaf entry
//! count LOOKED like it would overflow, computed by simulating the insert with
//! a placeholder physical block. A physically contiguous append merges into
//! its neighbouring extent instead of adding an entry, so no metadata block was
//! ever allocated and the charge stayed — every grown directory over-reported
//! `st_blocks`/`du` and over-consumed quota (`e2fsck`: "i_blocks is 74, should
//! be 42" for a 21-block htree directory).
//!
//! `e2fsck -fn` is the authority: it recomputes `i_blocks` from the extent tree.

extern crate alloc;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::idmap::Idmap;

const MINI: &[u8] = include_bytes!("mini.img");
const HTREE: &[u8] = include_bytes!("htree.img");
const SECTOR: u32 = 512;
const ROOT_INO: u32 = 2;

fn build_disk(image: &[u8]) -> (Arc<dyn BlockDevice>, u64) {
    let cap = (image.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: image.to_vec(), ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
    (disk, cap)
}

fn dump_disk(disk: &Arc<dyn BlockDevice>, cap: u64) -> std::vec::Vec<u8> {
    let mut req = BlockRequest::new_read(0, cap as u32, SECTOR);
    disk.submit_sync(&mut req).unwrap();
    req.buffer
}

/// `e2fsck -fn`: Some(true) clean, Some(false) errors, None when unavailable.
fn e2fsck_clean(bytes: &[u8]) -> Option<bool> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let uniq = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(std::format!("oxide-ext4-iblocks-{}-{}.img", std::process::id(), uniq));
    {
        let mut f = std::fs::File::create(&path).ok()?;
        f.write_all(bytes).ok()?;
    }
    let out = std::process::Command::new("e2fsck").arg("-fn").arg(&path).output();
    let _ = std::fs::remove_file(&path);
    match out {
        Ok(o) => {
            if !o.status.success() {
                eprintln!("--- e2fsck stdout ---\n{}", String::from_utf8_lossy(&o.stdout));
            }
            Some(o.status.success())
        }
        Err(_) => None,
    }
}

fn assert_fsck(disk: &Arc<dyn BlockDevice>, cap: u64, what: &str) {
    match e2fsck_clean(&dump_disk(disk, cap)) {
        Some(true) => {}
        Some(false) => panic!("e2fsck reported errors: {what}"),
        None => eprintln!("e2fsck not available — skipped fsck assertion ({what})"),
    }
}

/// The bug in its original shape: an htree directory grown by leaf splits.
/// Every block the directory owns is a data block (the extent tree stays inline
/// at depth 0), so `i_blocks` must be exactly `size / block_size` blocks' worth
/// of sectors — 42, not 74.
#[test]
fn grown_htree_dir_charges_one_block_per_data_block() {
    let (disk, cap) = build_disk(HTREE);
    {
        let m = ext4::Mount::open(disk.clone()).unwrap();
        let bs = m.sb.block_size as u64;
        let spb = m.sb.sectors_per_block() as u64;
        let dino = m.lookup_path(b"/bigdir").unwrap();
        let free0 = m.state_free_blocks();
        let blocks0 = m.read_inode(dino).unwrap().size / bs;
        for i in 0..360 {
            let name = std::format!("split_probe_entry_{i:05}");
            m.create_file(dino, name.as_bytes(), 0o644, 0, 0).unwrap();
        }
        let node = m.read_inode(dino).unwrap();
        let data_blocks = node.size / bs;
        assert!(data_blocks > 15, "the splits must actually have grown the dir (got {data_blocks} blocks)");
        // Only the directory allocates here (the new files are all size 0), so
        // the allocator delta is the exact block count the inode owns.
        let consumed = free0 - m.state_free_blocks();
        assert_eq!(consumed, data_blocks - blocks0, "no metadata block is allocated for a depth-0 extent tree");
        assert_eq!(node.i_blocks, data_blocks * spb,
            "i_blocks must count the {data_blocks} blocks the dir really owns, not a predicted split");
    }
    assert_fsck(&disk, cap, "htree dir grown by leaf splits");
}

/// Contiguous appends merge into one extent: the inline root never overflows,
/// so not one metadata block may be charged however long the run gets.
#[test]
fn contiguous_appends_charge_no_metadata_block() {
    let (disk, cap) = build_disk(MINI);
    {
        let m = ext4::Mount::open(disk.clone()).unwrap();
        let bs = m.sb.block_size as usize;
        let spb = m.sb.sectors_per_block() as u64;
        let f = m.create_file(ROOT_INO, b"contig.bin", 0o644, 0, 0).unwrap();
        let free0 = m.state_free_blocks();
        const N: u64 = 60;
        for _ in 0..N { m.append_block(f, &std::vec![0x5A; bs]).unwrap(); }
        let node = m.read_inode(f).unwrap();
        let consumed = free0 - m.state_free_blocks();
        assert_eq!(consumed, N, "a contiguous run allocates exactly one block per append");
        assert_eq!(node.i_blocks, N * spb, "i_blocks tracks the blocks actually allocated");
    }
    assert_fsck(&disk, cap, "contiguous file appends");
}

/// Fragmented growth DOES allocate extent-tree metadata (the inline root
/// promotes to depth 1, then the leaf splits). Those blocks are real and must
/// be charged — and the run of contiguous appends that follows must not add any
/// further charge, which is the depth>0 half of the same prediction bug.
#[test]
fn fragmented_then_contiguous_growth_charges_exactly_what_it_allocates() {
    let (disk, cap) = build_disk(MINI);
    {
        let m = ext4::Mount::open(disk.clone()).unwrap();
        let bs = m.sb.block_size as usize;
        let spb = m.sb.sectors_per_block() as u64;
        let a = m.create_file(ROOT_INO, b"frag_a.bin", 0o644, 0, 0).unwrap();
        let b = m.create_file(ROOT_INO, b"frag_b.bin", 0o644, 0, 0).unwrap();
        let free0 = m.state_free_blocks();
        // Interleaving two files makes every appended block physically
        // isolated: one extent record each, so the extent tree deepens.
        const FRAG: usize = 100;
        for _ in 0..FRAG {
            m.append_block(a, &std::vec![0xA1; bs]).unwrap();
            m.append_block(b, &std::vec![0xB2; bs]).unwrap();
        }
        let (flags_a, _g) = m.inode_flags_gen(a).unwrap();
        assert!(flags_a & ext4::inode::EXT4_EXTENTS_FL != 0, "extent-mapped");
        let consumed_frag = free0 - m.state_free_blocks();
        assert!(consumed_frag > (2 * FRAG) as u64,
            "fragmenting must have allocated extent-tree metadata blocks (consumed {consumed_frag})");

        // Now a contiguous run on `a` alone: each block merges into the extent
        // the previous append created, so only data blocks may be consumed.
        let free1 = m.state_free_blocks();
        const RUN: u64 = 40;
        for _ in 0..RUN { m.append_block(a, &std::vec![0xA1; bs]).unwrap(); }
        assert_eq!(free1 - m.state_free_blocks(), RUN,
            "a merging append allocates its data block and nothing else");

        let node = m.read_inode(a).unwrap();
        assert_eq!(node.size, (FRAG as u64 + RUN) * bs as u64);
        // i_blocks covers data + the surviving extent-tree metadata, so it must
        // exceed the data-only total but stay well under a per-append charge.
        let data_sectors = (FRAG as u64 + RUN) * spb;
        assert!(node.i_blocks > data_sectors, "extent-tree metadata is charged too");
        assert!(node.i_blocks < data_sectors + RUN * spb,
            "the contiguous run must not charge a metadata block per append (i_blocks={})", node.i_blocks);
    }
    assert_fsck(&disk, cap, "fragmented deep tree then contiguous run");
}

/// mkdir takes exactly one block for the `.`/`..` block.
#[test]
fn mkdir_charges_only_its_first_block() {
    let (disk, cap) = build_disk(MINI);
    {
        let m = ext4::Mount::open(disk.clone()).unwrap();
        let spb = m.sb.sectors_per_block() as u64;
        let free0 = m.state_free_blocks();
        let d = m.create_dir(ROOT_INO, b"freshdir", 0o755, 0, 0).unwrap();
        assert_eq!(free0 - m.state_free_blocks(), 1, "mkdir allocates one data block");
        assert_eq!(m.read_inode(d).unwrap().i_blocks, spb, "and charges exactly that block");
    }
    assert_fsck(&disk, cap, "fresh mkdir");
}

/// rmdir gives every block back — the uncharge side of the same accounting.
#[test]
fn rmdir_returns_every_block_the_dir_was_charged() {
    let (disk, cap) = build_disk(HTREE);
    {
        let m = ext4::Mount::open(disk.clone()).unwrap();
        let spb = m.sb.sectors_per_block() as u64;
        let bs = m.sb.block_size as u64;
        let free0 = m.state_free_blocks();
        let d = m.create_dir(ROOT_INO, b"doomed", 0o755, 0, 0).unwrap();
        for i in 0..120 {
            let name = std::format!("victim_{i:04}");
            m.create_file(d, name.as_bytes(), 0o644, 0, 0).unwrap();
        }
        let node = m.read_inode(d).unwrap();
        assert!(node.size > bs, "the dir grew past its first block");
        assert_eq!(node.i_blocks, (node.size / bs) * spb, "grown linear/htree dir charge is exact");
        for i in 0..120 {
            let name = std::format!("victim_{i:04}");
            // `Mount::unlink` only orphans; this test is the last reference, so
            // it evicts too (an image with a live orphan list is not fsck-clean).
            let out = m.unlink(d, name.as_bytes()).unwrap();
            assert!(out.orphaned(), "last link gone");
            m.free_orphan_inode(out.ino).unwrap();
        }
        m.rmdir(ROOT_INO, b"doomed").unwrap();
        assert_eq!(m.state_free_blocks(), free0, "rmdir returns every block the dir owned");
    }
    assert_fsck(&disk, cap, "mkdir + grow + rmdir");
}

/// `stat` must report the same number the filesystem persisted: `st_blocks`
/// comes from the on-disk `i_blocks`, not from a size-derived estimate, so an
/// over-charge would have been visible to `du` and to quota alike.
#[test]
fn stat_st_blocks_matches_the_on_disk_i_blocks() {
    let (disk, _cap) = build_disk(HTREE);
    let m = ext4::rootfs::Ext4Mount::open(disk).unwrap();
    let st = m.state();
    let bs = st.mount.sb.block_size as u64;
    let spb = st.mount.sb.sectors_per_block() as u64;
    st.mkdir_at(b"/statdir", 0o755).expect("mkdir");
    let dino = st.mount.lookup_path(b"/statdir").unwrap();
    for i in 0..150 {
        let name = std::format!("s_{i:04}");
        st.mount.create_file(dino, name.as_bytes(), 0o644, 0, 0).unwrap();
    }
    let raw = st.mount.read_inode(dino).unwrap();
    assert!(raw.size > bs, "the dir grew past its first block");
    let node = st.lookup_inode_any(b"/statdir").expect("lookup statdir");
    let k = node.getattr(&Idmap::identity());
    assert_eq!(k.blocks, raw.i_blocks, "st_blocks is the on-disk i_blocks, one source of truth");
    assert_eq!(k.blocks, (raw.size / bs) * spb, "and that count is the dir's real block count");
}

/// The depth>0 half of the same prediction, which failed LOUDLY rather than
/// over-charging: when the merging append landed on a leaf sitting exactly at
/// its entry limit, the predicted charge said "this insert splits the leaf"
/// while the real insert allocated nothing, and `append_block` rejected the
/// mismatch as `CorruptExtentTree` — a write error for a perfectly ordinary
/// append. Sweeping the fragmentation depth walks that boundary (it lands at
/// `FRAG == 83` on this fixture).
#[test]
fn merging_append_onto_a_full_extent_leaf_succeeds() {
    let mut last: Option<(Arc<dyn BlockDevice>, u64)> = None;
    for frag in 60..=100usize {
        let (disk, cap) = build_disk(HTREE);
        {
            let m = ext4::Mount::open(disk.clone()).unwrap();
            let bs = m.sb.block_size as usize;
            let a = m.create_file(ROOT_INO, b"leaf_a.bin", 0o644, 0, 0).unwrap();
            let b = m.create_file(ROOT_INO, b"leaf_b.bin", 0o644, 0, 0).unwrap();
            for _ in 0..frag {
                for ino in [a, b] {
                    m.append_block(ino, &std::vec![0x33; bs])
                        .unwrap_or_else(|e| panic!("fragmenting append (frag={frag}): {e:?}"));
                }
            }
            for k in 0..60 {
                m.append_block(a, &std::vec![0x33; bs])
                    .unwrap_or_else(|e| panic!("merging append #{k} at frag={frag}: {e:?}"));
            }
        }
        last = Some((disk, cap));
    }
    let (disk, cap) = last.unwrap();
    assert_fsck(&disk, cap, "merging appends across a full extent leaf");
}
