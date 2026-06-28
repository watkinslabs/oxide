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
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: image.to_vec(),
    };
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
        let f = m.create_file(2, b"newfile.bin", 0o644).unwrap();
        let payload: std::vec::Vec<u8> = (0..(bs as u32 * 2 + 100)).map(|i| (i & 0xFF) as u8).collect();
        m.write_at(f, bs as u64 - 50, &payload).unwrap();

        // 2) mkdir + populate it (grows the new dir, exercises tail csum).
        let d = m.create_dir(2, b"newdir", 0o755).unwrap();
        for i in 0..40u32 {
            let mut name = std::vec::Vec::new();
            name.extend_from_slice(b"child_");
            name.extend_from_slice(std::format!("{:03}", i).as_bytes());
            let c = m.create_file(d, &name, 0o644).unwrap();
            m.append_block(c, &std::vec![0xEE; bs]).unwrap();
        }

        // 3) truncate grow then shrink.
        let t = m.create_file(2, b"trunc.bin", 0o644).unwrap();
        for _ in 0..3 { m.append_block(t, &std::vec![0x11; bs]).unwrap(); }
        m.truncate_inode(t, 5 * bs as u64).unwrap();         // grow (zero-fill)
        m.truncate_inode(t, bs as u64 + 10).unwrap();        // shrink

        // 4) symlinks (fast + slow) and a device node.
        m.create_symlink(2, b"fastln", b"target").unwrap();
        let long: std::vec::Vec<u8> = std::vec![b'a'; 120];
        m.create_symlink(2, b"slowln", &long).unwrap();
        m.create_mknod(2, b"nulldev", ext4::inode::S_IFCHR | 0o666, (1 << 8) | 3).unwrap();

        // 5) unlink one file (frees inode + blocks).
        m.unlink(2, b"newfile.bin").unwrap();
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
        let n = m.create_file(2, b"deep.bin", 0o644).unwrap();
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
        let f = m.create_file(2, b"filler.bin", 0o644).unwrap();
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
        let child = m.create_file(dino, new_name, 0o644).unwrap();
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
