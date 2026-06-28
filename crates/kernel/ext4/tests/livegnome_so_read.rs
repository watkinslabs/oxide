//! B232 repro: read a small .so fully through the ext4 mount path and
//! compare to the on-disk file. Targets the live-gnome 8 GB root image.
//! Skips (passes) if the image is absent so CI stays green.

extern crate alloc;
use alloc::sync::Arc;
use std::cell::RefCell;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use block::{BlockDevice, BlockRequest, BlockOp, KResult};

const IMG: &str = "/home/nd/oxide/oxide-images/output/live-gnome-x86_64-root.img";
const LIB: &str = "/home/nd/oxide/oxide-images/work/root-live-gnome-x86_64/usr/lib64/libcap-ng.so.0.0.0";
const SECTOR: u32 = 512;

struct FileDisk { f: RefCell<File>, cap: u64 }
unsafe impl Send for FileDisk {}
unsafe impl Sync for FileDisk {}

impl BlockDevice for FileDisk {
    fn block_size(&self) -> u32 { SECTOR }
    fn capacity_blocks(&self) -> u64 { self.cap }
    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> {
        match req.op {
            BlockOp::Read => {
                let off = req.start_block * SECTOR as u64;
                let len = (req.len_blocks * SECTOR) as usize;
                if req.buffer.len() < len { req.buffer.resize(len, 0); }
                let mut f = self.f.borrow_mut();
                f.seek(SeekFrom::Start(off)).unwrap();
                f.read_exact(&mut req.buffer[..len]).unwrap();
                Ok(())
            }
            _ => Ok(()),
        }
    }
    fn flush(&self) -> KResult<()> { Ok(()) }
}

fn read_full(m: &ext4::Mount, ino: u32) -> Vec<u8> {
    let inode = m.read_inode(ino).expect("read_inode");
    let bs = m.sb.block_size as usize;
    let total = inode.size as usize;
    let n_blocks = (total + bs - 1) / bs;
    let mut out = Vec::with_capacity(total);
    for k in 0..n_blocks {
        let blk = match m.read_file_block(&inode, k as u32) {
            Ok(b) => b,
            Err(ext4::MountError::NotFound) => std::vec![0u8; bs],
            Err(e) => panic!("read_file_block {k}: {:?}", e),
        };
        let take = std::cmp::min(bs, total - out.len());
        out.extend_from_slice(&blk[..take]);
    }
    out
}

fn check_one(m: &ext4::Mount, path: &str, disk_path: &str) {
    let ino = m.lookup_path(path.as_bytes()).expect("lookup lib");
    let got = read_full(m, ino);
    let mut want = Vec::new();
    File::open(disk_path).unwrap().read_to_end(&mut want).unwrap();
    eprintln!("[{path}] size: fs={} disk={}", got.len(), want.len());
    assert_eq!(got.len(), want.len(), "size mismatch {path}");
    let mut first = None;
    for i in 0..got.len() { if got[i] != want[i] { first = Some(i); break; } }
    if let Some(i) = first {
        let page = i & !0xfff;
        eprintln!("FIRST DIVERGENCE {path} at 0x{:x} (page 0x{:x}): fs=0x{:02x} disk=0x{:02x}",
            i, page, got[i], want[i]);
        for j in (page..(page + 0x1000).min(got.len())).step_by(16) {
            let a = &got[j..(j + 16).min(got.len())];
            let b = &want[j..(j + 16).min(want.len())];
            if a != b { eprintln!("  0x{:04x} fs={:02x?}", j, a); eprintln!("         disk={:02x?}", b); }
        }
        panic!("content mismatch {path} at 0x{:x}", i);
    }
    eprintln!("MATCH: {path} read through ext4 == on-disk");
}

#[test]
fn livegnome_failing_libs_match_disk() {
    let f = match File::open(IMG) { Ok(f) => f, Err(_) => { eprintln!("SKIP: no image"); return; } };
    let len = f.metadata().unwrap().len();
    let disk: Arc<dyn BlockDevice> = Arc::new(FileDisk { f: RefCell::new(f), cap: len / SECTOR as u64 });
    let m = ext4::Mount::open(disk).expect("mount");
    let base = "/home/nd/oxide/oxide-images/work/root-live-gnome-x86_64";
    let _ = LIB;
    check_one(&m, "/usr/lib64/libcap-ng.so.0.0.0", &format!("{base}/usr/lib64/libcap-ng.so.0.0.0"));
    check_one(&m, "/usr/lib64/libaudit.so.1.0.0",  &format!("{base}/usr/lib64/libaudit.so.1.0.0"));
    check_one(&m, "/usr/lib64/libpcre2-8.so.0.14.0", &format!("{base}/usr/lib64/libpcre2-8.so.0.14.0"));
}
