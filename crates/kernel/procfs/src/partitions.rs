// /proc/partitions — the live block-device registry (Linux genhd
// `show_partition`). Replaces the header-only static stub. One row per
// registered disk: major, minor, size in 1 KiB blocks, name.
#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

pub struct ProcPartitionsInode;

struct VecFmt<'a>(&'a mut Vec<u8>);
impl<'a> core::fmt::Write for VecFmt<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result { self.0.extend_from_slice(s.as_bytes()); Ok(()) }
}

impl ProcPartitionsInode {
    fn body() -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(256);
        out.extend_from_slice(b"major minor  #blocks  name\n\n");
        for d in block::registry::snapshot() {
            let (maj, min) = block::registry::major_minor(&d.name, d.index);
            // /proc/partitions #blocks counts 1 KiB blocks (sectors/2).
            let blocks = block::registry::size_512_sectors(
                d.dev.capacity_blocks(), d.dev.block_size()) / 2;
            let _ = core::fmt::Write::write_fmt(&mut VecFmt(&mut out), format_args!(
                "{maj:>4} {min:>7} {blocks:>10} {n}\n", n = d.name));
        }
        out
    }
}

impl Inode for ProcPartitionsInode {
    fn ino(&self) -> Ino { 0x3000_1023 }
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
