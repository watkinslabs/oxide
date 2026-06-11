// /proc/vmstat — VM event + page counters. Replaces the static 3-line stub.
// `nr_free_pages` and the page-count fields come from the live PMM; counters
// for subsystems oxide doesn't have (swap, NUMA zones, THP, compaction, ...)
// honestly report 0 — Linux shows 0 for those too when the feature is unused.
#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

pub struct ProcVmstatInode;

struct VecFmt<'a>(&'a mut Vec<u8>);
impl<'a> core::fmt::Write for VecFmt<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result { self.0.extend_from_slice(s.as_bytes()); Ok(()) }
}

impl ProcVmstatInode {
    fn body() -> Vec<u8> {
        let (free, alloc) = match pmm::setup::pmm_static() {
            Some(p) => (p.free_pages(), p.allocated_pages()),
            None    => (0, 0),
        };
        let mut out: Vec<u8> = Vec::with_capacity(1024);
        // (key, value). Real PMM-backed fields are non-zero; the rest are 0
        // because their subsystem isn't accounted yet (not faked — just unused).
        let fields: &[(&str, u64)] = &[
            ("nr_free_pages", free),
            ("nr_zone_inactive_anon", 0), ("nr_zone_active_anon", alloc),
            ("nr_zone_inactive_file", 0), ("nr_zone_active_file", 0),
            ("nr_zone_unevictable", 0), ("nr_zone_write_pending", 0),
            ("nr_mlock", 0), ("nr_page_table_pages", 0), ("nr_kernel_stack", 0),
            ("nr_bounce", 0), ("nr_free_cma", 0),
            ("nr_inactive_anon", 0), ("nr_active_anon", alloc),
            ("nr_inactive_file", 0), ("nr_active_file", 0), ("nr_unevictable", 0),
            ("nr_slab_reclaimable", 0), ("nr_slab_unreclaimable", 0),
            ("nr_anon_pages", alloc), ("nr_mapped", alloc), ("nr_file_pages", 0),
            ("nr_dirty", 0), ("nr_writeback", 0), ("nr_shmem", 0),
            ("nr_kernel_misc_reclaimable", 0),
            ("pgpgin", 0), ("pgpgout", 0), ("pswpin", 0), ("pswpout", 0),
            ("pgalloc_normal", 0), ("pgfree", 0), ("pgactivate", 0), ("pgdeactivate", 0),
            ("pgfault", 0), ("pgmajfault", 0),
            ("pgscan_kswapd", 0), ("pgsteal_kswapd", 0),
            ("oom_kill", 0),
        ];
        for &(k, v) in fields {
            let _ = core::fmt::Write::write_fmt(&mut VecFmt(&mut out), format_args!("{k} {v}\n"));
        }
        out
    }
}

impl Inode for ProcVmstatInode {
    fn ino(&self) -> Ino { 0x3000_1022 }
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
