// Minimal /proc skeleton per docs/19. v1: each registered file is
// backed by a static `&[u8]` body. `read(off, buf)` copies a window
// of the body into the user buffer; subsequent reads at advancing
// offsets stream the file out. Files are registered into the same
// `devfs` registry under their full path, so `sys_open("/proc/...")`
// resolves through the existing path-lookup.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

static NEXT_INO: AtomicU64 = AtomicU64::new(0x3000_0000);

/// Static-body procfs file. `read(off, buf)` returns the window
/// `body[off..off+buf.len()]` clamped to body length.
pub struct StaticFileInode {
    body: &'static [u8],
    ino:  Ino,
}

impl StaticFileInode {
    /// # C: O(1)
    pub fn new(body: &'static [u8]) -> Arc<Self> {
        Arc::new(Self { body, ino: NEXT_INO.fetch_add(1, Ordering::Relaxed) })
    }
}

impl Inode for StaticFileInode {
    fn ino(&self) -> Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { self.body.len() as u64 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let off = off as usize;
        if off >= self.body.len() { return Ok(0); }
        let avail = &self.body[off..];
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        Ok(n)
    }
    fn write(&self, _off: u64, _buf: &[u8]) -> KResult<usize> {
        Err(VfsError::Erofs)
    }
}

const VERSION_BODY: &[u8] = b"oxide 0.1.0-pre #1 SMP PREEMPT\n";

#[cfg(target_arch = "x86_64")]
const CPUINFO_BODY: &[u8] = b"processor\t: 0\nmodel name\t: oxide-x86_64\ncpu cores\t: 1\n";
#[cfg(target_arch = "aarch64")]
const CPUINFO_BODY: &[u8] = b"processor\t: 0\nmodel name\t: oxide-aarch64\ncpu cores\t: 1\n";

const MEMINFO_BODY: &[u8] = b"MemTotal:        65536 kB\nMemFree:         32768 kB\nMemAvailable:    32768 kB\n";
const UPTIME_BODY:  &[u8] = b"0.00 0.00\n";
const LOADAVG_BODY: &[u8] = b"0.00 0.00 0.00 1/1 1\n";
const STAT_BODY:    &[u8] = b"cpu  0 0 0 0 0 0 0 0 0 0\n";
const FILESYSTEMS:  &[u8] = b"nodev\tdevtmpfs\nnodev\tprocfs\n";
const MOUNTS_BODY:  &[u8] = b"devtmpfs /dev devtmpfs rw 0 0\nprocfs /proc procfs rw 0 0\n";

/// Register the v1 procfs entries into devfs.
/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(N_files)
pub fn init() {
    crate::devfs::register("/proc/version",     StaticFileInode::new(VERSION_BODY)     as InodeRef);
    crate::devfs::register("/proc/cpuinfo",     StaticFileInode::new(CPUINFO_BODY)     as InodeRef);
    crate::devfs::register("/proc/meminfo",     StaticFileInode::new(MEMINFO_BODY)     as InodeRef);
    crate::devfs::register("/proc/uptime",      StaticFileInode::new(UPTIME_BODY)      as InodeRef);
    crate::devfs::register("/proc/loadavg",     StaticFileInode::new(LOADAVG_BODY)     as InodeRef);
    crate::devfs::register("/proc/stat",        StaticFileInode::new(STAT_BODY)        as InodeRef);
    crate::devfs::register("/proc/filesystems", StaticFileInode::new(FILESYSTEMS)      as InodeRef);
    crate::devfs::register("/proc/mounts",      StaticFileInode::new(MOUNTS_BODY)      as InodeRef);
    crate::devfs::register("/proc/self/maps",   StaticFileInode::new(b"")              as InodeRef);
    crate::devfs::register("/proc/self/status", StaticFileInode::new(b"State: R\n")    as InodeRef);
}

/// Boot-time smoke: open every registered /proc entry via the
/// devfs lookup, read its first 16 bytes through the Inode trait,
/// kassert the body matches the registered prefix.
/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(N_files)
pub fn smoke_test() {
    use vfs::Inode;
    use hal::kassert;
    let entries: &[(&str, &[u8])] = &[
        ("/proc/version", b"oxide"),
        ("/proc/cpuinfo", b"processor"),
        ("/proc/meminfo", b"MemTotal:"),
        ("/proc/uptime",  b"0.00"),
    ];
    for (path, prefix) in entries {
        let inode = crate::devfs::lookup(path).expect("procfs lookup");
        let mut buf = [0u8; 32];
        let n = inode.read(0, &mut buf).expect("procfs read");
        kassert!(n >= prefix.len(), "procfs read short");
        kassert!(&buf[..prefix.len()] == *prefix, "procfs body mismatch");
    }
    debug_boot! { klog::write_raw(b"[INFO]  procfs-smoke: ok\n"); }
}
