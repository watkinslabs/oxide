//! An allocation request is a maximum, not a minimum.
//!
//! The reference's allocator returns the extent it managed to find and the
//! caller maps that much and comes back for the rest; only finding nothing at
//! all is out of space. Serving a request solely as one contiguous run reports
//! a full filesystem whenever the free space is merely fragmented, and
//! writeback hands that refusal to a writing process as an I/O error -- which
//! is one of the two things that stopped `systemd-hwdb` mid-boot.
//!
//! Skips (passes) when `mke2fs`/`e2fsck` are absent so CI stays green.

extern crate alloc;
mod common;

use alloc::sync::Arc;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::process::Command;
use std::sync::Mutex;

use block::{BlockDevice, BlockOp, BlockRequest, KResult};

const SECTOR: u32 = 512;
const BS: u64 = 4096;
/// One 128 KiB cluster, the unit page writeback asks for.
const CLUSTER_BLOCKS: u64 = 32;

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
    fn flush(&self) -> KResult<()> { Ok(()) }
}

fn have(tool: &str) -> bool { Command::new(tool).arg("-V").output().is_ok() }

fn fsck(path: &std::path::Path) -> (bool, std::string::String) {
    let out = Command::new("e2fsck").arg("-fn").arg(path).output().expect("e2fsck");
    let s = std::format!("{}{}",
        std::string::String::from_utf8_lossy(&out.stdout),
        std::string::String::from_utf8_lossy(&out.stderr));
    (out.status.success(), s)
}

fn build(tag: &str) -> Option<std::path::PathBuf> {
    if !have("mke2fs") || !have("e2fsck") { eprintln!("SKIP: mke2fs/e2fsck absent"); return None; }
    let mut path = std::env::temp_dir();
    path.push(std::format!("oxide-ext4-shortrun-{}-{tag}.img", std::process::id()));
    let _ = std::fs::remove_file(&path);
    if !Command::new("truncate").arg("-s").arg("96M").arg(&path).status().ok()?.success() { return None }
    if !Command::new("mke2fs")
        .args(["-q", "-t", "ext4", "-O", "metadata_csum,64bit,^has_journal",
               "-I", "256", "-b", "4096"])
        .arg(&path).status().ok()?.success() { return None }
    Some(path)
}

fn open_rw(path: &std::path::Path) -> ext4::Mount {
    let f = OpenOptions::new().read(true).write(true).open(path).unwrap();
    let cap = f.metadata().unwrap().len() / SECTOR as u64;
    let disk: Arc<dyn BlockDevice> = Arc::new(RwFileDisk { f: Mutex::new(f), cap });
    ext4::Mount::open(disk).expect("mount")
}

/// Leave the free space in one-cluster holes: fill the volume with
/// cluster-sized files and remove every other one.
fn fragment(m: &ext4::Mount, dir: u32) -> u64 {
    let payload = std::vec![0xC3u8; (CLUSTER_BLOCKS * BS) as usize];
    let mut made = std::vec::Vec::new();
    for i in 0..4000u32 {
        let name = std::format!("frag{i:05}");
        let Ok(ino) = m.create_file(dir, name.as_bytes(), 0o644, 0, 0) else { break };
        if m.write_at(ino, 0, &payload).is_err() {
            // The file that ran the volume out of room is not part of the
            // fixture; take it back off the orphan list rather than leaving it.
            let out = m.unlink(dir, name.as_bytes()).expect("fixture unlink of the last file");
            if out.orphaned() { m.free_orphan_inode(out.ino).expect("fixture free of the last file"); }
            break;
        }
        made.push(name);
    }
    let mut holes = 0u64;
    for name in made.iter().step_by(2) {
        let out = m.unlink(dir, name.as_bytes())
            .unwrap_or_else(|e| panic!("fixture unlink {name}: {e:?}"));
        if out.orphaned() {
            m.free_orphan_inode(out.ino)
                .unwrap_or_else(|e| panic!("fixture free {name} (ino {}): {e:?}", out.ino));
            holes += 1;
        }
    }
    holes
}

#[test]
fn a_large_write_succeeds_when_the_free_space_is_only_fragmented() {
    let Some(path) = build("write") else { return };
    {
        let m = open_rw(&path);
        let dir = m.create_dir(2, b"frag", 0o755, 0, 0).expect("scratch dir");
        let holes = fragment(&m, dir);
        assert!(holes > 8, "fixture produced only {holes} holes");
        let free = m.sb.free_blocks_count;
        // Far more free space than the write needs -- just none of it in one run.
        let want_blocks = CLUSTER_BLOCKS * 8;
        assert!(free > want_blocks * 4, "fixture left only {free} free blocks");
        let ino = m.create_file(dir, b"big.bin", 0o644, 0, 0).expect("create");
        let payload = std::vec![0x5Au8; (want_blocks * BS) as usize];
        m.write_at(ino, 0, &payload).unwrap_or_else(|e|
            panic!("write of {want_blocks} blocks with {free} free: {e:?}"));
        // What was written must read back, across however many runs it took.
        let raw = m.read_inode(ino).expect("inode");
        assert_eq!(raw.size, payload.len() as u64, "i_size after a fragmented write");
        for blk in 0..want_blocks as u32 {
            let got = m.read_file_block(&raw, blk)
                .unwrap_or_else(|e| panic!("read block {blk} back: {e:?}"));
            assert!(got.iter().take(BS as usize).all(|&b| b == 0x5A),
                "block {blk} did not read back as written");
        }
    }
    let (ok, log) = fsck(&path);
    let _ = std::fs::remove_file(&path);
    assert!(ok, "image inconsistent after a fragmented large write:\n{log}");
}
