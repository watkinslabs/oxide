// /proc/stat — system-wide kernel counters per `19§4`.
//
// Body shape (per-CPU rows then aggregates):
//   cpu  <user> <nice> <sys> <idle> <iowait> <irq> <softirq> <steal> <guest> <gnice>
//   cpu0 <same>
//   intr 0
//   ctxt 0
//   btime <unix-seconds at boot>
//   processes <total spawned>
//   procs_running <runnable count>
//   procs_blocked 0
//   softirq 0 0 0 0 0 0 0 0 0 0
//
// v1: jiffies counters report 0 (no per-CPU tick accounting yet).
// btime and processes/procs_running come from live kernel state.

#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;

use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

pub struct ProcStatInode;

impl ProcStatInode {
    fn body() -> Vec<u8> {
        let (total, running) = sched::live::registry::live_counts();
        let btime = crate::syscalls::time::boot_unix_seconds();
        let mut out: Vec<u8> = Vec::with_capacity(192);
        let _ = core::fmt::Write::write_fmt(&mut VecFmt(&mut out), format_args!(
            "cpu  0 0 0 0 0 0 0 0 0 0\n\
             cpu0 0 0 0 0 0 0 0 0 0 0\n\
             intr 0\n\
             ctxt 0\n\
             btime {btime}\n\
             processes {total}\n\
             procs_running {running}\n\
             procs_blocked 0\n\
             softirq 0 0 0 0 0 0 0 0 0 0\n",
        ));
        out
    }
}

impl Inode for ProcStatInode {
    fn ino(&self) -> Ino { 0x3000_1020 }
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

struct VecFmt<'a>(&'a mut Vec<u8>);
impl<'a> core::fmt::Write for VecFmt<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}
