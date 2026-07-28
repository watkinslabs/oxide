//! Evidence repro: boot corrupts the gnome rootfs (e2fsck: "Group 13 block
//! bitmap does not match checksum / differences"). Group 13 is INITIALIZED but
//! group 14 is BLOCK_UNINIT with its bitmap block adjacent to group 13's. This
//! drives block allocation into the BLOCK_UNINIT group on a WRITABLE copy of the
//! clean image and runs `e2fsck -fn` to catch the on-disk corruption.
//!
//! Skips (passes) if the clean image or e2fsck is absent so CI stays green.

extern crate alloc;
mod common;
use alloc::sync::Arc;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::process::Command;
use std::sync::Mutex;

use block::{BlockDevice, BlockRequest, BlockOp, KResult};

const CLEAN: &str = "/home/nd/oxide/images/out/gnome-x86_64-root.img";
const ARM_ROOT: &str = "/home/nd/oxide/kernel/target/builds/default/root-aarch64.img";
const SECTOR: u32 = 512;

struct RwFileDisk { f: Mutex<File>, cap: u64 }

impl BlockDevice for RwFileDisk {
    fn block_size(&self) -> u32 { SECTOR }
    fn capacity_blocks(&self) -> u64 { self.cap }
    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> {
        let off = req.start_block * SECTOR as u64;
        let len = (req.len_blocks * SECTOR) as usize;
        let mut f = self.f.lock().unwrap();
        f.seek(SeekFrom::Start(off)).unwrap();
        match req.op {
            BlockOp::Read => {
                if req.buffer.len() < len { req.buffer.resize(len, 0); }
                f.read_exact(&mut req.buffer[..len]).unwrap();
            }
            BlockOp::Write => { f.write_all(&req.buffer[..len]).unwrap(); }
            _ => {}
        }
        Ok(())
    }
    fn flush(&self) -> KResult<()> { self.f.lock().unwrap().flush().unwrap(); Ok(()) }
}

fn e2fsck_clean(path: &str) -> (bool, String) {
    // -f force, -n no-changes (read-only check). exit 0 = clean.
    let out = Command::new("e2fsck").args(["-fn", path]).output().expect("e2fsck");
    let s = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    (out.status.success(), s)
}

fn copy_checked(src: &str, tag: &str) -> Option<String> {
    if File::open(src).is_err() { eprintln!("SKIP: no image at {src}"); return None; }
    if Command::new("e2fsck").arg("-V").output().is_err() { eprintln!("SKIP: no e2fsck"); return None; }
    let tmp = format!("{}/{}", std::env::temp_dir().display(), tag);
    std::fs::copy(src, &tmp).expect("copy image");
    let (ok0, log0) = e2fsck_clean(&tmp);
    assert!(ok0, "source image copy already dirty:\n{log0}");
    Some(tmp)
}

fn open_rw(path: &str) -> (Arc<dyn BlockDevice>, ext4::Mount) {
    let f = OpenOptions::new().read(true).write(true).open(path).unwrap();
    let cap = f.metadata().unwrap().len() / SECTOR as u64;
    let disk: Arc<dyn BlockDevice> = Arc::new(RwFileDisk { f: Mutex::new(f), cap });
    let m = ext4::Mount::open(disk.clone()).expect("mount");
    (disk, m)
}

#[test]
fn boot_like_balloc_into_uninit_group_keeps_fsck_clean() {
    if File::open(CLEAN).is_err() { eprintln!("SKIP: no clean image at {CLEAN}"); return; }
    if Command::new("e2fsck").arg("-V").output().is_err() { eprintln!("SKIP: no e2fsck"); return; }

    // Work on a private copy so we never touch the pristine image.
    let tmp = format!("{}/balloc_uninit_repro.img", std::env::temp_dir().display());
    std::fs::copy(CLEAN, &tmp).expect("copy image");

    // Baseline: the clean copy must fsck clean.
    let (ok0, log0) = e2fsck_clean(&tmp);
    assert!(ok0, "PRE-boot image already dirty:\n{log0}");

    {
        let f = OpenOptions::new().read(true).write(true).open(&tmp).unwrap();
        let cap = f.metadata().unwrap().len() / SECTOR as u64;
        let disk: Arc<dyn BlockDevice> = Arc::new(RwFileDisk { f: Mutex::new(f), cap });
        let m = ext4::Mount::open(disk).expect("mount");
        eprintln!("groups={} bpg={} bs={} free_blocks={}",
                  m.sb.group_count(), m.sb.blocks_per_group, m.sb.block_size, m.sb.free_blocks_count);
        // Faithful churn like boot's tmp/var: mkdir a scratch dir, then create
        // files with real data (forces inode alloc in INODE_UNINIT groups + block
        // alloc into the high BLOCK_UNINIT groups), unlinking older ones so blocks
        // + inodes recycle. Enough data to spill allocation into groups 13/14.
        let root = 2u32; // ext4 root inode
        let dir = m.create_dir(root, b"repro_scratch", 0o755, 0, 0).expect("mkdir");
        let payload = std::vec![0xA5u8; 256 * 1024]; // 256 KiB → 64 blocks each
        let mut live: std::collections::VecDeque<u32> = std::collections::VecDeque::new();
        for i in 0..400u32 {
            let name = std::format!("f{i:04}");
            let ino = match m.create_file(dir, name.as_bytes(), 0o644, 0, 0) {
                Ok(n) => n,
                Err(e) => { eprintln!("create stopped at {i}: {:?}", e); break; }
            };
            if let Err(e) = m.write_at(ino, 0, &payload) {
                eprintln!("write stopped at {i}: {:?}", e); break;
            }
            live.push_back(ino);
            // Keep ~40 files live; unlink+free the oldest so blocks recycle.
            if live.len() > 40 {
                let old = live.pop_front().unwrap();
                let oname = std::format!("f{:04}", i - 40);
                // `Mount::unlink` orphans the inode; with no VFS layer above
                // this test IS the last reference, so it runs the eviction.
                let out = m.unlink(dir, oname.as_bytes()).expect("unlink");
                if out.orphaned() { m.free_orphan_inode(out.ino).expect("evict orphan"); }
                let _ = old;
            }
        }
        eprintln!("churn done, {} files still live", live.len());
    }

    let (ok1, log1) = e2fsck_clean(&tmp);
    let _ = std::fs::remove_file(&tmp);
    assert!(ok1, "POST-balloc image is CORRUPT (reproduced the boot corruption):\n{log1}");
}

/// Boot runs ext4 ops CONCURRENTLY across CPUs; this hammers one shared mount
/// from several threads (create+write+unlink) to expose a block-bitmap/gdt RMW
/// race — the difference between the (clean) single-threaded churn above and the
/// corruption a multi-CPU boot leaves. e2fsck must stay clean.
#[test]
fn concurrent_churn_keeps_fsck_clean() {
    if File::open(CLEAN).is_err() { eprintln!("SKIP: no clean image"); return; }
    if Command::new("e2fsck").arg("-V").output().is_err() { eprintln!("SKIP: no e2fsck"); return; }
    let tmp = format!("{}/balloc_concurrent_repro.img", std::env::temp_dir().display());
    std::fs::copy(CLEAN, &tmp).expect("copy image");
    let (ok0, log0) = e2fsck_clean(&tmp);
    assert!(ok0, "PRE image dirty:\n{log0}");
    {
        let f = OpenOptions::new().read(true).write(true).open(&tmp).unwrap();
        let cap = f.metadata().unwrap().len() / SECTOR as u64;
        let disk: Arc<dyn BlockDevice> = Arc::new(RwFileDisk { f: Mutex::new(f), cap });
        let m = Arc::new(ext4::Mount::open(disk).expect("mount"));
        // Each thread owns its own scratch dir so only the shared block/inode
        // allocator + gdt_buf + superblock counters are contended.
        let payload = std::vec![0x5Au8; 128 * 1024];
        let mut hs = std::vec::Vec::new();
        for t in 0..4u32 {
            let m = m.clone();
            let payload = payload.clone();
            hs.push(std::thread::spawn(move || {
                let dir = m.create_dir(2, std::format!("t{t}").as_bytes(), 0o755, 0, 0).expect("mkdir");
                let mut live: std::collections::VecDeque<(u32, String)> = std::collections::VecDeque::new();
                for i in 0..150u32 {
                    let name = std::format!("f{i:04}");
                    let ino = match m.create_file(dir, name.as_bytes(), 0o644, 0, 0) {
                        Ok(n) => n, Err(_) => break };
                    if m.write_at(ino, 0, &payload).is_err() { break; }
                    live.push_back((ino, name));
                    if live.len() > 20 {
                        let (_o, on) = live.pop_front().unwrap();
                        if let Ok(out) = m.unlink(dir, on.as_bytes()) {
                            if out.orphaned() { let _ = m.free_orphan_inode(out.ino); }
                        }
                    }
                }
            }));
        }
        for h in hs { let _ = h.join(); }
    }
    let (ok1, log1) = e2fsck_clean(&tmp);
    let _ = std::fs::remove_file(&tmp);
    assert!(ok1, "POST concurrent churn image is CORRUPT (SMP ext4 race reproduced):\n{log1}");
}

#[test]
fn arm_hwdb_rewrite_and_replacement_keep_fsck_clean() {
    let Some(tmp) = copy_checked(ARM_ROOT, "arm_hwdb_rewrite_repro.img") else { return; };
    {
        let (disk, m) = open_rw(&tmp);
        let udev = m.lookup_path(b"/etc/udev").expect("/etc/udev");
        let hwdb = m.lookup_path(b"/etc/udev/hwdb.bin").expect("/etc/udev/hwdb.bin");
        let old = m.read_inode(hwdb).expect("old hwdb inode");
        let size = old.size as usize;
        let mut payload = std::vec![0u8; size];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = (i as u32).wrapping_mul(1103515245).wrapping_add(12345).to_le_bytes()[1];
        }

        m.truncate_inode(hwdb, 0).expect("truncate existing hwdb");
        m.write_at(hwdb, 0, &payload).expect("rewrite existing hwdb");

        let tmp_ino = m.create_file(udev, b".hwdb.bin.oxide-repro", 0o444, 0, 0)
            .expect("create replacement hwdb candidate");
        m.write_at(tmp_ino, 0, &payload).expect("write replacement hwdb candidate");
        drop(m);
        disk.flush().expect("flush image");
    }
    let (ok1, log1) = e2fsck_clean(&tmp);
    let _ = std::fs::remove_file(&tmp);
    assert!(ok1, "POST hwdb rewrite/replacement image is CORRUPT:\n{log1}");
}

#[test]
fn arm_hwdb_batched_framecache_rewrite_keeps_fsck_clean() {
    common::boot_hosted_pmm();
    let Some(tmp) = copy_checked(ARM_ROOT, "arm_hwdb_framecache_repro.img") else { return; };
    {
        let (disk, raw) = open_rw(&tmp);
        let m = Arc::new(raw);
        let st = ext4::rootfs::RootfsState::new(m.clone());
        let hwdb = m.lookup_path(b"/etc/udev/hwdb.bin").expect("/etc/udev/hwdb.bin");
        let old = m.read_inode(hwdb).expect("old hwdb inode");
        let size = old.size as usize;
        let mut payload = std::vec![0u8; size];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = (i as u32).wrapping_mul(1664525).wrapping_add(1013904223).to_le_bytes()[2];
        }

        m.begin_batch();
        m.truncate_inode(hwdb, 0).expect("truncate existing hwdb");
        let inode = st.wrap_file(hwdb).expect("wrap hwdb");
        let mut off = 0usize;
        while off < payload.len() {
            let n = (1531usize).min(payload.len() - off);
            assert_eq!(inode.write(off as u64, &payload[off..off + n]).expect("buffered hwdb write"), n);
            off += n;
        }
        inode.i_mapping().unwrap().writeback().expect("framecache writeback");
        m.commit_batch().expect("commit batched hwdb rewrite");
        drop(inode);
        drop(st);
        drop(m);
        disk.flush().expect("flush image");
    }
    let (ok1, log1) = e2fsck_clean(&tmp);
    let _ = std::fs::remove_file(&tmp);
    assert!(ok1, "POST batched framecache hwdb rewrite image is CORRUPT:\n{log1}");
}
