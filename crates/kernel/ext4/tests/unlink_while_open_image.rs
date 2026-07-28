//! POSIX unlink-while-open over a real ext4 image, with `e2fsck` as the gate.
//!
//! `unlink(2)` removes the NAME. The inode, its data blocks and its inode slot
//! survive until the last open file description closes — Linux implements this
//! with `ext4_orphan_add` at `__ext4_unlink` (`fs/ext4/namei.c`) and the
//! truncate+free deferred to `ext4_evict_inode` (`fs/ext4/inode.c`), reached
//! from `iput_final` (`fs/inode.c`). It is the mechanism behind `mkstemp`,
//! compiler temporaries and shared-memory shims.
//!
//! Freeing at unlink time hands those blocks to the next allocation while the
//! first reader still holds the fd: silent cross-file data corruption, with the
//! reader seeing another file's bytes. `blocks_are_not_reallocated_while_the_fd_lives`
//! is the assertion that catches exactly that.

extern crate alloc;
mod common;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use std::io::Write;
use std::sync::atomic::{AtomicU32, Ordering};

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::{CreateCtx, Dentry, File, InodeRef, OpenFlags, SuperBlock};

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;

fn build_disk() -> (Arc<dyn BlockDevice>, u64) {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: IMAGE.to_vec(),
    };
    disk.submit_sync(&mut req).expect("seed memdisk");
    (disk, cap)
}

fn mount(disk: Arc<dyn BlockDevice>) -> (Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>) {
    common::boot_hosted_pmm();
    let m = ext4::rootfs::Ext4Mount::open(disk).expect("Ext4Mount::open");
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb(fs, root, 0xE471_0AE4, String::from("ext4"));
    (m, sb)
}

fn open_file(inode: &InodeRef) -> (Arc<File>, Arc<Dentry>) {
    let dentry = Dentry::new_root(inode.clone());
    (File::new(inode.clone(), dentry.clone(), OpenFlags::O_RDWR), dentry)
}

/// Every physical block an inode's extent tree currently owns.
/// Buffered writes sit in the per-inode frame cache until writeback; force
/// them out so the extent tree and the free-block counters are on disk.
fn sync(sb: &Arc<SuperBlock>) { sb.sync_fs(true).expect("sync_fs"); }

fn phys_blocks(m: &ext4::rootfs::Ext4Mount, ino: u32) -> Vec<u64> {
    let mut out = Vec::new();
    for (_lba, phys, len, _unwritten) in m.state().mount.extent_map(ino).expect("extent map") {
        for i in 0..len as u64 { out.push(phys + i); }
    }
    out
}

fn dump_disk(disk: &Arc<dyn BlockDevice>, cap: u64) -> Vec<u8> {
    let mut req = BlockRequest {
        op: BlockOp::Read, start_block: 0, len_blocks: cap as u32,
        buffer: alloc::vec![0u8; (cap as usize) * SECTOR as usize],
    };
    disk.submit_sync(&mut req).expect("read back");
    req.buffer
}

/// `e2fsck -fn`. `None` when e2fsck is not installed (skip, do not fail).
fn e2fsck_clean(bytes: &[u8]) -> Option<bool> {
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let uniq = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(std::format!("oxide-unlink-open-fsck-{}-{}.img", std::process::id(), uniq));
    { let mut f = std::fs::File::create(&path).ok()?; f.write_all(bytes).ok()?; }
    let out = std::process::Command::new("e2fsck").arg("-fn").arg(&path).output();
    let _ = std::fs::remove_file(&path);
    match out {
        Ok(o) => {
            if !o.status.success() {
                eprintln!("--- e2fsck stdout ---\n{}", String::from_utf8_lossy(&o.stdout));
                eprintln!("--- e2fsck stderr ---\n{}", String::from_utf8_lossy(&o.stderr));
            }
            Some(o.status.success())
        }
        Err(_) => None,
    }
}

fn assert_fsck_clean(disk: &Arc<dyn BlockDevice>, cap: u64, what: &str) {
    match e2fsck_clean(&dump_disk(disk, cap)) {
        Some(true)  => {}
        Some(false) => { eprintln!("--- image state: {what} ---"); panic!("e2fsck reported errors"); }
        None        => eprintln!("e2fsck not available — skipped fsck assertion"),
    }
}

#[test]
fn data_written_before_unlink_is_still_readable_through_the_fd() {
    let (disk, _cap) = build_disk();
    let (m, sb) = mount(disk);
    let root = sb.s_root_inode().expect("root inode");

    let inode = root.create_child("keepopen.bin", 0o644, &CreateCtx::root()).expect("create");
    let ino = inode.ino() as u32;
    let raw_ino = m.state().mount.lookup_path(b"/keepopen.bin").expect("lookup");
    let (file, _dentry) = open_file(&inode);

    let payload: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
    assert_eq!(file.pwrite(&payload, 0).expect("write"), payload.len());

    root.unlink_child("keepopen.bin").expect("unlink");

    // The name is gone the moment unlink returns...
    assert!(m.state().mount.lookup_path(b"/keepopen.bin").is_err(), "name removed");
    assert_eq!(inode.nlink(), 0, "in-core link count follows the on-disk one");
    // ... but the inode is alive on the orphan list, not freed.
    assert_eq!(m.state().mount.read_sb_last_orphan().expect("orphan head"), raw_ino);
    assert_eq!(m.state().mount.read_inode(raw_ino).expect("raw").links_count, 0);

    // THE assertion: the fd still reads exactly what it wrote.
    let mut back = alloc::vec![0u8; payload.len()];
    assert_eq!(file.pread(&mut back, 0).expect("read after unlink"), payload.len());
    assert_eq!(back, payload, "unlinked-but-open file must keep its contents");

    // ... and still writes.
    let more: Vec<u8> = (0..4096u32).map(|i| (i % 97) as u8 ^ 0xA5).collect();
    assert_eq!(file.pwrite(&more, 8192).expect("write after unlink"), more.len());
    let mut back2 = alloc::vec![0u8; more.len()];
    assert_eq!(file.pread(&mut back2, 8192).expect("read back after unlink"), more.len());
    assert_eq!(back2, more, "writes through the fd survive the unlink");

    let _ = ino;
}

#[test]
fn blocks_are_not_reallocated_while_the_fd_lives() {
    // The corruption this defect produced: unlink frees the blocks, the next
    // create hands the SAME blocks to a second file, and the first reader —
    // whose fd is still open — sees the second file's bytes.
    let (disk, _cap) = build_disk();
    let (m, sb) = mount(disk);
    let root = sb.s_root_inode().expect("root inode");

    let victim = root.create_child("victim.bin", 0o644, &CreateCtx::root()).expect("create victim");
    let victim_ino = m.state().mount.lookup_path(b"/victim.bin").expect("lookup victim");
    let (vfile, _vdentry) = open_file(&victim);
    let payload: Vec<u8> = (0..16384u32).map(|i| (i % 233) as u8).collect();
    assert_eq!(vfile.pwrite(&payload, 0).expect("write victim"), payload.len());
    sync(&sb);
    let victim_blocks = phys_blocks(&m, victim_ino);
    assert!(!victim_blocks.is_empty(), "victim owns data blocks");

    root.unlink_child("victim.bin").expect("unlink victim");

    // Allocate a second file large enough to have taken the victim's blocks.
    let thief = root.create_child("thief.bin", 0o644, &CreateCtx::root()).expect("create thief");
    let thief_ino = m.state().mount.lookup_path(b"/thief.bin").expect("lookup thief");
    let (tfile, _tdentry) = open_file(&thief);
    let poison: Vec<u8> = alloc::vec![0x5Au8; 16384];
    assert_eq!(tfile.pwrite(&poison, 0).expect("write thief"), poison.len());
    sync(&sb);

    let thief_blocks = phys_blocks(&m, thief_ino);
    for b in &thief_blocks {
        assert!(!victim_blocks.contains(b),
            "block {b} handed to a second file while the first file's fd is still open");
    }

    // And the victim's fd still sees ITS data, not the thief's poison.
    let mut back = alloc::vec![0u8; payload.len()];
    assert_eq!(vfile.pread(&mut back, 0).expect("read victim after thief wrote"), payload.len());
    assert_eq!(back, payload, "reader saw another file's contents");
}

#[test]
fn last_close_frees_the_inode_and_leaves_the_image_fsck_clean() {
    let (disk, cap) = build_disk();
    {
        let (m, sb) = mount(disk.clone());
        let root = sb.s_root_inode().expect("root inode");
        let pre_blocks = m.state().mount.state_free_blocks();
        let pre_inodes = m.state().mount.state_free_inodes();

        let inode = root.create_child("closeme.bin", 0o644, &CreateCtx::root()).expect("create");
        let raw_ino = m.state().mount.lookup_path(b"/closeme.bin").expect("lookup");
        let (file, dentry) = open_file(&inode);
        let payload: Vec<u8> = (0..12288u32).map(|i| (i % 199) as u8).collect();
        assert_eq!(file.pwrite(&payload, 0).expect("write"), payload.len());

        sync(&sb);
        root.unlink_child("closeme.bin").expect("unlink");
        assert!(m.state().mount.state_free_blocks() < pre_blocks, "blocks still charged while open");
        assert!(m.state().mount.state_free_inodes() < pre_inodes, "inode still charged while open");

        // Close: `File::drop` -> `dput` -> `SuperBlock::iput` -> `drop_inode`
        // -> `ext4_evict_inode`, which is what actually frees.
        drop(file);
        drop(dentry);
        vfs::file::iput(inode);

        assert_eq!(m.state().mount.state_free_blocks(), pre_blocks, "blocks returned on last close");
        assert_eq!(m.state().mount.state_free_inodes(), pre_inodes, "inode returned on last close");
        assert_eq!(m.state().mount.read_sb_last_orphan().expect("orphan head"), 0, "orphan list drained");
        assert_eq!(m.state().mount.read_inode(raw_ino).expect("raw").links_count, 0);
    }
    // Mount dropped -> `put_super` reaps any residue and marks the fs clean.
    assert_fsck_clean(&disk, cap, "after unlink-while-open + last close");
}

#[test]
fn an_orphan_still_held_at_umount_is_reaped_and_the_image_stays_clean() {
    // The fd outlives nothing here — it is dropped only when the mount goes
    // away, so `put_super`'s reap (Linux `evict_inodes` at
    // `generic_shutdown_super`) is the path under test. Either way the image
    // must not be handed to e2fsck with a populated orphan list.
    let (disk, cap) = build_disk();
    {
        let (m, sb) = mount(disk.clone());
        let root = sb.s_root_inode().expect("root inode");
        let inode = root.create_child("held.bin", 0o644, &CreateCtx::root()).expect("create");
        let (file, _dentry) = open_file(&inode);
        assert_eq!(file.pwrite(&alloc::vec![0x7Eu8; 6000], 0).expect("write"), 6000);
        root.unlink_child("held.bin").expect("unlink");
        assert_ne!(m.state().mount.read_sb_last_orphan().expect("orphan head"), 0);
        // Everything drops here, mount included.
    }
    assert_fsck_clean(&disk, cap, "after an orphan survived to umount");
}
