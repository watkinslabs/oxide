// /proc/diskstats — per-disk I/O counters (Linux `diskstats_show`). One row
// per registered block device, fields per the kernel ABI. Timing fields
// (ms_reading/…) and *_merged are 0 (oxide's sync block layer doesn't track
// per-request latency or request merging yet); the real counters
// (reads/writes/sectors/in-flight/discards/flushes) come from the block
// layer's per-disk `DiskStats` (block::stats), fed at every submit_sync.
#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

pub struct ProcDiskstatsInode;

struct VecFmt<'a>(&'a mut Vec<u8>);
impl<'a> core::fmt::Write for VecFmt<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result { self.0.extend_from_slice(s.as_bytes()); Ok(()) }
}

impl ProcDiskstatsInode {
    fn body() -> Vec<u8> {
        use core::sync::atomic::Ordering;
        let mut out: Vec<u8> = Vec::with_capacity(256);
        for d in block::registry::snapshot() {
            let (maj, min) = block::registry::major_minor(&d.name, d.index);
            let (reads, sr, writes, sw, inflight) = d.stats.snapshot();
            let discards = d.stats.discards.load(Ordering::Relaxed);
            let sd = d.stats.sectors_discarded.load(Ordering::Relaxed);
            let flushes = d.stats.flushes.load(Ordering::Relaxed);
            // Linux fields: maj min name  rd rd_merged rd_sec rd_ms  wr wr_merged
            // wr_sec wr_ms  inflight io_ms weighted_io_ms  dsc dsc_merged dsc_sec
            // dsc_ms  fl fl_ms. Untracked (timing/merged) report 0.
            let _ = core::fmt::Write::write_fmt(&mut VecFmt(&mut out), format_args!(
                "{maj:>4} {min:>7} {n} {reads} 0 {sr} 0 {writes} 0 {sw} 0 {inflight} 0 0 {discards} 0 {sd} 0 {flushes} 0\n",
                n = d.name));
        }
        out
    }
}

impl Inode for ProcDiskstatsInode {
    fn ino(&self) -> Ino { 0x3000_1024 }
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
