//! End-to-end acceptance: drive the real ext4 write path against a
//! metadata_csum image, dump the resulting bytes, and run stock
//! `e2fsck -fn`. A clean exit proves every metadata structure we
//! touched (inode csum, dir tail csum, bitmap/GDT csum, extent tail,
//! counters, i_blocks, extra_isize) is Linux-valid — the DONE bar.
//!
//! If `e2fsck` is not on PATH the fsck assertion is skipped (the data
//! round-trip assertions still run), so CI without e2fsprogs stays green.

extern crate alloc;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;

const MINI: &[u8] = include_bytes!("mini.img");
const HTREE: &[u8] = include_bytes!("htree.img");
const SECTOR: u32 = 512;

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

/// Run `e2fsck -fn` on the image bytes. Returns Some(true) if e2fsck
/// reports clean, Some(false) if it found errors, None if e2fsck is
/// unavailable (test should treat None as "skip the fsck assertion").
fn e2fsck_clean(bytes: &[u8]) -> Option<bool> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let uniq = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(std::format!("oxide-ext4-fsck-{}-{}.img", std::process::id(), uniq));
    {
        let mut f = std::fs::File::create(&path).ok()?;
        f.write_all(bytes).ok()?;
    }
    let out = std::process::Command::new("e2fsck")
        .arg("-fn").arg(&path).output();
    let _ = std::fs::remove_file(&path);
    match out {
        Ok(o) => {
            if !o.status.success() {
                eprintln!("--- e2fsck stdout ---\n{}", String::from_utf8_lossy(&o.stdout));
                eprintln!("--- e2fsck stderr ---\n{}", String::from_utf8_lossy(&o.stderr));
            }
            Some(o.status.success())          // e2fsck exits 0 only when clean
        }
        Err(_) => None,                       // not installed → skip
    }
}

#[test]
fn write_path_produces_e2fsck_clean_image() {
    let (disk, cap) = build_disk(MINI);
    {
        let m = ext4::Mount::open(disk.clone()).unwrap();
        let bs = m.sb.block_size as usize;

        // 1) create file + write across an extent/block boundary.
        let f = m.create_file(2, b"newfile.bin", 0o644, 0, 0).unwrap();
        let payload: std::vec::Vec<u8> = (0..(bs as u32 * 2 + 100)).map(|i| (i & 0xFF) as u8).collect();
        m.write_at(f, bs as u64 - 50, &payload).unwrap();

        // 2) mkdir + populate it (grows the new dir, exercises tail csum).
        let d = m.create_dir(2, b"newdir", 0o755, 0, 0).unwrap();
        for i in 0..40u32 {
            let mut name = std::vec::Vec::new();
            name.extend_from_slice(b"child_");
            name.extend_from_slice(std::format!("{:03}", i).as_bytes());
            let c = m.create_file(d, &name, 0o644, 0, 0).unwrap();
            m.append_block(c, &std::vec![0xEE; bs]).unwrap();
        }

        // 3) truncate grow then shrink.
        let t = m.create_file(2, b"trunc.bin", 0o644, 0, 0).unwrap();
        for _ in 0..3 { m.append_block(t, &std::vec![0x11; bs]).unwrap(); }
        m.truncate_inode(t, 5 * bs as u64).unwrap();         // grow (zero-fill)
        m.truncate_inode(t, bs as u64 + 10).unwrap();        // shrink

        // 4) symlinks (fast + slow) and a device node.
        m.create_symlink(2, b"fastln", b"target", 0, 0).unwrap();
        let long: std::vec::Vec<u8> = std::vec![b'a'; 120];
        m.create_symlink(2, b"slowln", &long, 0, 0).unwrap();
        m.create_mknod(2, b"nulldev", ext4::inode::S_IFCHR | 0o666, (1 << 8) | 3, 0, 0).unwrap();

        // 5) unlink one file. `Mount::unlink` only orphans it — with no VFS
        // layer above, this test is the last reference, so it also evicts
        // (blocks + inode come back here). An image left with a populated
        // orphan list is NOT fsck-clean, which is what this assert proves.
        let out = m.unlink(2, b"newfile.bin").unwrap();
        assert!(out.orphaned(), "last link gone");
        m.free_orphan_inode(out.ino).unwrap();
    }
    let bytes = dump_disk(&disk, cap);
    match e2fsck_clean(&bytes) {
        Some(true)  => {}
        Some(false) => panic!("e2fsck reported errors on the written image"),
        None        => eprintln!("e2fsck not available — skipped fsck assertion"),
    }
}

#[test]
fn deep_extent_tree_file_is_e2fsck_clean() {
    // Force an external extent tree (depth >= 1) so the extent-block
    // tail csum + i_blocks metadata accounting are exercised, then
    // confirm e2fsck accepts the result.
    let (disk, cap) = build_disk(MINI);
    {
        let m = ext4::Mount::open(disk.clone()).unwrap();
        let bs = m.sb.block_size as usize;
        let n = m.create_file(2, b"deep.bin", 0o644, 0, 0).unwrap();
        // A spacer held allocated between appends breaks contiguity → many
        // separate extents → inline root (4) overflows → promote to depth 1.
        let mut spacers = std::vec::Vec::new();
        for i in 0..6u8 {
            spacers.push(m.alloc_block(0).unwrap());
            m.append_block(n, &std::vec![i; bs]).unwrap();
        }
        let inode = m.read_inode(n).unwrap();
        assert!(ext4::parse_extent_header(&inode.i_block).unwrap().depth >= 1,
                "test must build an external extent tree");
        // Release the spacers so the bitmap has no leaked (unreferenced)
        // blocks — the fragmented extent layout is already locked in.
        for s in spacers { m.free_block(s).unwrap(); }
    }
    let bytes = dump_disk(&disk, cap);
    match e2fsck_clean(&bytes) {
        Some(true)  => {}
        Some(false) => panic!("e2fsck reported errors on deep-extent file"),
        None        => eprintln!("e2fsck not available — skipped fsck assertion"),
    }
}

#[test]
fn enospc_surfaces_and_leaves_fs_clean() {
    let (disk, cap) = build_disk(MINI);
    {
        let m = ext4::Mount::open(disk.clone()).unwrap();
        let bs = m.sb.block_size as usize;
        let f = m.create_file(2, b"filler.bin", 0o644, 0, 0).unwrap();
        // Append until the block allocator runs dry.
        let mut hit_enospc = false;
        for _ in 0..(m.sb.blocks_count_lo as usize + 16) {
            match m.append_block(f, &std::vec![0x5A; bs]) {
                Ok(_) => {}
                Err(ext4::MountError::NoSpace) => { hit_enospc = true; break; }
                Err(e) => panic!("unexpected append error: {:?}", e),
            }
        }
        assert!(hit_enospc, "expected NoSpace once the fs filled up");
        assert_eq!(m.state_free_blocks(), 0, "all blocks consumed at ENOSPC");
    }
    // A failed (ENOSPC) append must not have left a half-committed write:
    // the image must still be e2fsck-clean.
    let bytes = dump_disk(&disk, cap);
    match e2fsck_clean(&bytes) {
        Some(true)  => {}
        Some(false) => panic!("e2fsck reported errors after ENOSPC"),
        None        => eprintln!("e2fsck not available — skipped fsck assertion"),
    }
}

#[test]
fn htree_insert_lands_in_correct_leaf_and_stays_clean() {
    let (disk, cap) = build_disk(HTREE);
    let new_name = b"freshly_inserted_entry_name";
    {
        let m = ext4::Mount::open(disk.clone()).unwrap();
        // /bigdir is an indexed (htree) directory (inode discovered by path).
        let dino = m.lookup_path(b"/bigdir").unwrap();
        let dnode = m.read_inode(dino).unwrap();
        let (flags, _gen) = m.inode_flags_gen(dino).unwrap();
        assert!(flags & ext4::EXT4_INDEX_FL != 0, "bigdir must be htree-indexed");
        // Create a brand-new file *inside* the htree dir — create_file's
        // dir_link routes through the htree hash-descent insert path and
        // maintains the child's link count correctly.
        let child = m.create_file(dino, new_name, 0o644, 0, 0).unwrap();
        // The linear leaf scan must find it (Linux's hash lookup will too,
        // because we inserted into the hash-covering leaf).
        let found = m.lookup_in_dir(&dnode, new_name).unwrap();
        assert_eq!(found, child, "inserted htree entry resolves");
    }
    let bytes = dump_disk(&disk, cap);
    match e2fsck_clean(&bytes) {
        Some(true)  => {}
        Some(false) => panic!("e2fsck reported errors after htree insert"),
        None        => eprintln!("e2fsck not available — skipped fsck assertion"),
    }
}

#[test]
fn fallocate_unwritten_extents_then_write_is_e2fsck_clean() {
    // Lane 10: fallocate now maps the range as UNWRITTEN extents (no eager
    // zero-writes). Verify: reads serve zeros, a write CONVERTS the touched
    // subrange to written (data visible, rest still zeros), and the on-disk
    // extent tree (with unwritten flags + a converted split) is e2fsck-clean.
    let (disk, cap) = build_disk(MINI);
    let bs;
    {
        let m = ext4::Mount::open(disk.clone()).unwrap();
        bs = m.sb.block_size as usize;
        let f = m.create_file(2, b"journal.bin", 0o644, 0, 0).unwrap();
        // Preallocate 8 blocks (grows size); no data written yet.
        m.fallocate_inode(f, 0, (bs * 8) as u64, false).unwrap();
        let inode = m.read_inode(f).unwrap();
        assert_eq!(inode.size, (bs * 8) as u64);
        // Every preallocated block reads as zeros (unwritten -> zero-fill).
        for lb in 0..8 {
            assert!(m.read_file_block(&inode, lb).unwrap().iter().all(|&b| b == 0),
                "unwritten block {lb} reads zeros");
        }
        // Write real data into blocks 2..=4 (converts those unwritten -> written).
        let payload: std::vec::Vec<u8> = (0..(bs as u32 * 3)).map(|i| ((i & 0x7F) | 0x80) as u8).collect();
        m.write_at(f, (bs * 2) as u64, &payload).unwrap();
        let inode2 = m.read_inode(f).unwrap();
        // Written blocks show the data; still-unwritten blocks read zeros.
        assert_eq!(m.read_file_block(&inode2, 2).unwrap(), payload[..bs], "converted block 2 has data");
        assert_eq!(m.read_file_block(&inode2, 4).unwrap(), payload[bs*2..bs*3], "converted block 4 has data");
        assert!(m.read_file_block(&inode2, 0).unwrap().iter().all(|&b| b == 0), "block 0 still unwritten -> zeros");
        assert!(m.read_file_block(&inode2, 7).unwrap().iter().all(|&b| b == 0), "block 7 still unwritten -> zeros");
    }
    // Remount: the data survives and the metadata is Linux-valid.
    {
        let m2 = ext4::Mount::open(disk.clone()).unwrap();
        let f = m2.lookup_path(b"/journal.bin").unwrap();
        let inode = m2.read_inode(f).unwrap();
        assert_eq!(m2.read_file_block(&inode, 3).unwrap()[0] & 0x80, 0x80, "converted data persisted");
        assert!(m2.read_file_block(&inode, 0).unwrap().iter().all(|&b| b == 0), "unwritten persisted as zeros");
    }
    let bytes = dump_disk(&disk, cap);
    match e2fsck_clean(&bytes) {
        Some(true)  => {}
        Some(false) => panic!("e2fsck reported errors after unwritten fallocate + write"),
        None        => eprintln!("e2fsck not available — skipped fsck assertion"),
    }
}

#[test]
fn sparse_write_past_eof_leaves_a_hole_not_zeros() {
    // A write landing far past EOF must leave the gap as a HOLE (Linux sparse
    // semantics), allocating only the written block(s) — NOT zero-filling the
    // whole span (the O(file-size) writeback stall the old code caused).
    let (disk, cap) = build_disk(MINI);
    {
        let m = ext4::Mount::open(disk.clone()).unwrap();
        let bs = m.sb.block_size as usize;
        let f = m.create_file(2, b"sparse.bin", 0o644, 0, 0).unwrap();
        let pre_free = m.state_free_blocks();
        // Write one block of data at logical block 100 (offset 100*bs).
        let payload = std::vec![0xA5u8; bs];
        m.write_at(f, (bs * 100) as u64, &payload).unwrap();
        let inode = m.read_inode(f).unwrap();
        assert_eq!(inode.size, (bs * 101) as u64, "size reflects the far write");
        // Only a FEW blocks were allocated (the written block + maybe an extent
        // metadata block), NOT ~100 — proving the gap is a hole.
        let used = pre_free - m.state_free_blocks();
        assert!(used <= 3, "sparse write allocated {used} blocks (must be a hole, not ~100)");
        // The gap reads as zeros; the written block reads the data.
        assert!(m.read_file_block(&inode, 50).unwrap().iter().all(|&b| b == 0), "gap block 50 is a hole -> zeros");
        assert_eq!(m.read_file_block(&inode, 100).unwrap(), payload, "written block 100 has data");
    }
    let bytes = dump_disk(&disk, cap);
    match e2fsck_clean(&bytes) {
        Some(true)  => {}
        Some(false) => panic!("e2fsck reported errors on the sparse file"),
        None        => eprintln!("e2fsck not available — skipped fsck assertion"),
    }
}

#[test]
fn htree_leaf_split_stays_e2fsck_clean() {
    // Lane 6/8: filling an indexed dir's leaves forces `htree_split` — allocate a
    // new leaf, redistribute entries by hash, add a dx_entry, re-stamp the
    // dx_tail csum. Create many files in /bigdir, confirm EVERY one resolves via
    // the hash-descent lookup, then e2fsck the result (validates leaf tails, the
    // new dx_entry, and the dx checksum).
    let (disk, cap) = build_disk(HTREE);
    const N: usize = 360; // htree.img has ~420 free inodes
    {
        let m = ext4::Mount::open(disk.clone()).unwrap();
        let dino = m.lookup_path(b"/bigdir").unwrap();
        let (flags, _g) = m.inode_flags_gen(dino).unwrap();
        assert!(flags & ext4::EXT4_INDEX_FL != 0, "bigdir is htree-indexed");
        for i in 0..N {
            let name = std::format!("split_probe_entry_{i:05}");
            m.create_file(dino, name.as_bytes(), 0o644, 0, 0)
                .unwrap_or_else(|e| panic!("create #{i} into htree dir: {e:?}"));
        }
        // Every inserted name must resolve through the htree hash lookup.
        let dnode = m.read_inode(dino).unwrap();
        for i in 0..N {
            let name = std::format!("split_probe_entry_{i:05}");
            m.lookup_in_dir(&dnode, name.as_bytes())
                .unwrap_or_else(|e| panic!("lookup #{i} after splits: {e:?}"));
        }
    }
    // Remount + re-lookup a sample to prove on-disk persistence, then e2fsck.
    {
        let m2 = ext4::Mount::open(disk.clone()).unwrap();
        let d2 = m2.lookup_path(b"/bigdir").unwrap();
        let n2 = m2.read_inode(d2).unwrap();
        for i in (0..N).step_by(37) {
            let name = std::format!("split_probe_entry_{i:05}");
            m2.lookup_in_dir(&n2, name.as_bytes()).unwrap_or_else(|e| panic!("remount lookup #{i}: {e:?}"));
        }
    }
    let bytes = dump_disk(&disk, cap);
    match e2fsck_clean(&bytes) {
        Some(true)  => {}
        Some(false) => panic!("e2fsck reported errors after htree leaf splits"),
        None        => eprintln!("e2fsck not available — skipped fsck assertion"),
    }
}

/// Lane 7: overflow a 1-level htree ROOT to force `htree_grow` (single→two
/// level). Generates a near-root-capacity indexed /bigdir with mke2fs, then
/// adds enough entries to overflow the dx_root; verifies every add resolves and
/// e2fsck accepts the grown 2-level tree. Skips cleanly if mke2fs is absent.
#[test]
fn htree_create_split_and_root_grow_stays_e2fsck_clean() {
    use std::process::Command;
    if Command::new("mke2fs").arg("-V").output().is_err() { eprintln!("SKIP: mke2fs absent"); return; }
    // A FRESH empty ext4 (1024-block, dir_index, metadata_csum). Our code then
    // mkdirs a dir and adds thousands of files: block 0 fills → htree_create
    // (linear→indexed), leaves fill → htree_split, and the dx_root fills → grow
    // (1→2 level). e2fsck validates the whole indexed tree we built.
    let base = std::env::temp_dir().join(std::format!("oxide-htbuild-{}", std::process::id()));
    std::fs::create_dir_all(&base).unwrap();
    let img = base.join("fresh.img");
    let ok = Command::new("mke2fs")
        .args(["-F", "-q", "-t", "ext4", "-b", "1024", "-O", "^has_journal,^resize_inode", "-N", "12000"])
        .arg(&img).arg("18000").status().map(|s| s.success()).unwrap_or(false);
    if !ok { let _ = std::fs::remove_dir_all(&base); eprintln!("SKIP: mke2fs failed"); return; }
    let bytes = std::fs::read(&img).unwrap();
    let _ = std::fs::remove_dir_all(&base);

    let cap = (bytes.len() as u64) / (SECTOR as u64);
    let disk: std::sync::Arc<block::MemDisk<sync::TaskList>> = block::MemDisk::new(SECTOR, cap);
    let mut req = block::BlockRequest { op: block::BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: bytes, ..Default::default() };
    use block::BlockDevice as _;
    disk.submit_sync(&mut req).unwrap();
    let dev: std::sync::Arc<dyn block::BlockDevice> = disk.clone();

    const N: usize = 6000; // > root capacity (~122 leaves × ~40) → forces the grow
    {
        let m = ext4::Mount::open(dev.clone()).unwrap();
        let dino = m.create_dir(2, b"idx", 0o755, 0, 0).unwrap();
        let flags0 = m.inode_flags_gen(dino).unwrap().0;
        assert_eq!(flags0 & ext4::EXT4_INDEX_FL, 0, "starts as a linear dir");
        for i in 0..N {
            let name = std::format!("f_{i:06}");
            m.create_file(dino, name.as_bytes(), 0o644, 0, 0)
                .unwrap_or_else(|e| panic!("create #{i}: {e:?}"));
        }
        // Now indexed and, at 6000 entries, grown to a 2-level tree.
        let flags1 = m.inode_flags_gen(dino).unwrap().0;
        assert_ne!(flags1 & ext4::EXT4_INDEX_FL, 0, "dir became htree-indexed (htree_create)");
        let dnode = m.read_inode(dino).unwrap();
        let level = m.read_file_block_meta(&dnode, 0).unwrap()[0x1E];
        eprintln!("htree indirect_levels after {N} creates = {level}");
        assert_eq!(level, 1, "root grew to a 2-level index (htree_grow)");
        // Every name resolves through the hash-descent lookup.
        for i in 0..N {
            let name = std::format!("f_{i:06}");
            m.lookup_in_dir(&dnode, name.as_bytes()).unwrap_or_else(|e| panic!("lookup #{i}: {e:?}"));
        }
    }
    // Remount + spot-check persistence, then e2fsck the built index.
    {
        let m2 = ext4::Mount::open(dev.clone()).unwrap();
        let d2 = m2.lookup_path(b"/idx").unwrap();
        let n2 = m2.read_inode(d2).unwrap();
        for i in (0..N).step_by(101) {
            let name = std::format!("f_{i:06}");
            m2.lookup_in_dir(&n2, name.as_bytes()).unwrap_or_else(|e| panic!("remount lookup #{i}: {e:?}"));
        }
    }
    let mut rreq = block::BlockRequest::new_read(0, cap as u32, SECTOR);
    disk.submit_sync(&mut rreq).unwrap();
    match e2fsck_clean(&rreq.buffer) {
        Some(true)  => {}
        Some(false) => panic!("e2fsck reported errors on the htree we built (create+split+grow)"),
        None        => eprintln!("e2fsck unavailable — skipped fsck"),
    }
}

#[test]
fn punch_hole_zeros_range_and_stays_e2fsck_clean() {
    // Lane 13: PUNCH_HOLE deallocates a middle range → holes (read zeros), keeps
    // data outside, zeros partial-block edges, leaves size unchanged. Test a few
    // patterns (whole-block interior, straddling edges, whole extent) then e2fsck.
    let (disk, cap) = build_disk(MINI);
    {
        let m = ext4::Mount::open(disk.clone()).unwrap();
        let bs = m.sb.block_size as usize;
        let f = m.create_file(2, b"punchme.bin", 0o644, 0, 0).unwrap();
        // Fill 10 blocks with a recognizable non-zero pattern.
        let data: std::vec::Vec<u8> = (0..(bs * 10)).map(|i| ((i % 251) + 1) as u8).collect();
        m.write_at(f, 0, &data).unwrap();

        // Punch whole blocks [3,6): offset 3*bs, len 3*bs.
        m.punch_hole_inode(f, (bs * 3) as u64, (bs * 3) as u64).unwrap();
        let inode = m.read_inode(f).unwrap();
        assert_eq!(inode.size, (bs * 10) as u64, "size unchanged by punch");
        for lb in 3..6 {
            assert!(m.read_file_block(&inode, lb).unwrap().iter().all(|&b| b == 0),
                "punched block {lb} reads zeros");
        }
        for lb in [0u32, 2, 6, 9] {
            assert!(m.read_file_block(&inode, lb).unwrap().iter().any(|&b| b != 0),
                "unpunched block {lb} keeps its data");
        }
        // Punch a sub-block range straddling block 7's start and inside block 8:
        // zero [7*bs + 100, 8*bs + 200). Partial edges zeroed, block 8 stays.
        m.punch_hole_inode(f, (bs * 7 + 100) as u64, (bs + 100) as u64).unwrap();
        let inode2 = m.read_inode(f).unwrap();
        let b7 = m.read_file_block(&inode2, 7).unwrap();
        assert!(b7[..100].iter().any(|&b| b != 0), "block 7 head kept");
        assert!(b7[100..].iter().all(|&b| b == 0), "block 7 tail zeroed");
        let b8 = m.read_file_block(&inode2, 8).unwrap();
        assert!(b8[..200].iter().all(|&b| b == 0), "block 8 head zeroed");
    }
    let bytes = dump_disk(&disk, cap);
    match e2fsck_clean(&bytes) {
        Some(true)  => {}
        Some(false) => panic!("e2fsck reported errors after punch_hole"),
        None        => eprintln!("e2fsck unavailable — skipped fsck"),
    }
}

#[test]
fn truncate_and_punch_preserve_external_xattr_i_blocks() {
    let (disk, cap) = build_disk(MINI);
    {
        let m = ext4::Mount::open(disk.clone()).unwrap();
        let bs = m.sb.block_size as usize;
        let spb = (m.sb.block_size / 512) as u64;
        let f = m.create_file(2, b"xattr-blocks.bin", 0o644, 0, 0).unwrap();
        m.write_at(f, 0, &std::vec![0x5a; bs * 3]).unwrap();
        m.store_xattrs(f, &[("user.large".into(), std::vec![0x33; 300])]).unwrap();

        let with_xattr = m.read_inode(f).unwrap();
        assert_eq!(with_xattr.i_blocks, spb * 4, "three data blocks plus external xattr");

        m.truncate_inode(f, bs as u64).unwrap();
        let truncated = m.read_inode(f).unwrap();
        assert_eq!(truncated.i_blocks, spb * 2, "truncate retains external xattr charge");

        m.punch_hole_inode(f, 0, bs as u64).unwrap();
        let punched = m.read_inode(f).unwrap();
        assert_eq!(punched.i_blocks, spb, "xattr block remains after all data is punched");
    }
    let bytes = dump_disk(&disk, cap);
    match e2fsck_clean(&bytes) {
        Some(true) => {}
        Some(false) => panic!("e2fsck reported errors after xattr truncate/punch"),
        None => eprintln!("e2fsck unavailable - skipped fsck"),
    }
}
