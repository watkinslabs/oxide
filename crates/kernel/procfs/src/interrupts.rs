// /proc/interrupts — per-CPU interrupt counters (Linux `show_interrupts`).
// CPU columns for each online CPU; one row per device line that has fired,
// plus the always-present LOC (local timer) and RES (resched IPI) summary
// rows. Counts come from arch_irq::irqstat (fed by the timer-IRQ dispatcher).
#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

pub struct ProcInterruptsInode;

struct VecFmt<'a>(&'a mut Vec<u8>);
impl<'a> core::fmt::Write for VecFmt<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result { self.0.extend_from_slice(s.as_bytes()); Ok(()) }
}

impl ProcInterruptsInode {
    fn body() -> Vec<u8> {
        use core::fmt::Write;
        use arch_irq::irqstat;
        let ncpu = (cpu::smp::online_count() as usize).clamp(1, cpu::MAX_CPUS);
        let mut out: Vec<u8> = Vec::with_capacity(256 + ncpu * 16);
        // Header: left-pad for the label column, then "CPUn" per CPU.
        out.extend_from_slice(b"        ");
        for c in 0..ncpu {
            let _ = write!(VecFmt(&mut out), "CPU{c:<7}");
        }
        out.push(b'\n');
        // Device lines that have fired at least once.
        for idx in 0..irqstat::NLINES {
            if irqstat::line_total(idx) == 0 { continue; }
            let _ = write!(VecFmt(&mut out), "{idx:>6}:");
            for c in 0..ncpu {
                let _ = write!(VecFmt(&mut out), " {:>10}", irqstat::line(idx, c));
            }
            let _ = write!(VecFmt(&mut out), "   PCI-MSI   {idx}\n");
        }
        // Summary rows (always present).
        out.extend_from_slice(b"   LOC:");
        for c in 0..ncpu { let _ = write!(VecFmt(&mut out), " {:>10}", irqstat::timer(c)); }
        out.extend_from_slice(b"   Local timer interrupts\n");
        out.extend_from_slice(b"   RES:");
        for c in 0..ncpu { let _ = write!(VecFmt(&mut out), " {:>10}", irqstat::resched(c)); }
        out.extend_from_slice(b"   Rescheduling interrupts\n");
        out
    }
}

impl Inode for ProcInterruptsInode {
    fn ino(&self) -> Ino { 0x3000_1025 }
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
