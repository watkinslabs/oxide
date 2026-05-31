// /proc/cmdline backed by the kernel's boot-cmdline slot.
//
// `crate::boot_cmdline::get` returns the bytes the bootloader passed
// (Limine `cmdline` on x86, FDT `/chosen/bootargs` on aarch64) or an
// arch-default until those parsers land.

#![cfg(target_os = "oxide-kernel")]

use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

pub struct ProcCmdlineInode;

impl Inode for ProcCmdlineInode {
    fn ino(&self) -> Ino { 0x3000_1010 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let body = crate::boot_cmdline::get();
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body[off..off + n]);
        Ok(n)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
}
