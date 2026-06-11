// /proc/buddyinfo — per-order free-block counts from the buddy allocator
// (Linux `frag_show`). One row per memory zone; oxide has a single
// Normal zone. Column `o` = number of free order-`o` blocks. Counts come
// live from the PMM (`free_orders()`).
#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

pub struct ProcBuddyinfoInode;

struct VecFmt<'a>(&'a mut Vec<u8>);
impl<'a> core::fmt::Write for VecFmt<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result { self.0.extend_from_slice(s.as_bytes()); Ok(()) }
}

impl ProcBuddyinfoInode {
    fn body() -> Vec<u8> {
        use core::fmt::Write;
        let mut out: Vec<u8> = Vec::with_capacity(256);
        let orders = match pmm::setup::pmm_static() {
            Some(p) => p.free_orders(),
            None => return out,
        };
        // Single Normal zone (oxide has no DMA/DMA32 split).
        let _ = write!(VecFmt(&mut out), "Node 0, zone   Normal");
        for c in orders.iter() {
            let _ = write!(VecFmt(&mut out), " {c:>6}");
        }
        out.push(b'\n');
        out
    }
}

impl Inode for ProcBuddyinfoInode {
    fn ino(&self) -> Ino { 0x3000_1027 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let body = Self::body();
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body[off..off + n]);
        Ok(n)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
}
