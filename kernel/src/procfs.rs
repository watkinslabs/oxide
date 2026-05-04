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

/// `/proc/self/maps` per `19§4`. Walks the current task's
/// AddressSpace VMA tree and emits one line per VMA in
/// `<start>-<end> <perms> <off> 00:00 <ino> <path>` form. v1
/// path/offset/inode are stubs.
pub struct ProcSelfMapsInode;

impl ProcSelfMapsInode {
    fn body() -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::with_capacity(1024);
        let cur = match crate::sched::current() { Some(c) => c, None => return out };
        // SAFETY: running task on this CPU; preempt-off; sole reader of the mm slot per the single-mutator invariant in `13§5`.
        let mm = match unsafe { cur.mm_ref() } { Some(m) => m.clone(), None => return out };
        for vma in mm.snapshot_vmas() {
            push_hex(&mut out, vma.start.as_u64());
            out.push(b'-');
            push_hex(&mut out, vma.end.as_u64());
            out.push(b' ');
            // perms: rwxp / rwxs (we only support PRIVATE backing today)
            let p = vma.prot;
            out.push(if p.contains(vmm::VmaProt::READ)  { b'r' } else { b'-' });
            out.push(if p.contains(vmm::VmaProt::WRITE) { b'w' } else { b'-' });
            out.push(if p.contains(vmm::VmaProt::EXEC)  { b'x' } else { b'-' });
            out.push(b'p');
            push(&mut out, b" 00000000 00:00 0 \n");
        }
        out
    }
}

impl Inode for ProcSelfMapsInode {
    fn ino(&self) -> Ino { 0x3000_1300 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let body = Self::body();
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let avail = &body[off..];
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        Ok(n)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
}

fn push_hex(v: &mut alloc::vec::Vec<u8>, mut n: u64) {
    if n == 0 { v.push(b'0'); return; }
    let mut buf = [0u8; 16]; let mut i = 0;
    while n > 0 {
        let nib = (n & 0xf) as u8;
        buf[i] = if nib < 10 { b'0' + nib } else { b'a' + (nib - 10) };
        n >>= 4; i += 1;
    }
    while i > 0 { i -= 1; v.push(buf[i]); }
}

/// `/proc/self/cmdline` per `19§4`. Reads `Task.cmdline` snapshot
/// (NUL-joined argv from the most recent execve). Falls back to
/// `Task.name` + NUL when no execve has run yet.
pub struct ProcSelfCmdlineInode;

impl Inode for ProcSelfCmdlineInode {
    fn ino(&self) -> Ino { 0x3000_1100 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let mut body = alloc::vec::Vec::with_capacity(64);
        let cur = crate::sched::current();
        // SAFETY: single-mutator per `13§5`; current task is the sole
        // writer to its own cmdline slot, and we are it on this CPU.
        let snapshot = cur.and_then(|c| unsafe { (*c.cmdline.get()).clone() });
        if let Some(s) = snapshot {
            push(&mut body, s.as_bytes());
        } else {
            let name = cur.map(|c| c.name).unwrap_or("init");
            push(&mut body, name.as_bytes());
            body.push(0);
        }
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let avail = &body[off..];
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        Ok(n)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
}

/// `/proc/self/stat` per `19§4` — single space-separated line of
/// fields. v1: pid, comm in parens, state R, ppid, then zeros to
/// pad to the canonical 52 fields.
pub struct ProcSelfStatInode;

impl Inode for ProcSelfStatInode {
    fn ino(&self) -> Ino { 0x3000_1200 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        use core::sync::atomic::Ordering;
        let mut body = alloc::vec::Vec::with_capacity(192);
        let cur = crate::sched::current();
        let tid  = cur.map(|c| c.tid as u64).unwrap_or(1);
        let ppid = cur.map(|c| c.parent_tid.load(Ordering::Acquire) as u64).unwrap_or(0);
        let name = cur.map(|c| c.name).unwrap_or("init");
        push_u64(&mut body, tid);
        push(&mut body, b" (");
        push(&mut body, name.as_bytes());
        push(&mut body, b") R ");
        push_u64(&mut body, ppid);
        // pad with zeros to fill enough fields for libc parsers.
        for _ in 0..48 { push(&mut body, b" 0"); }
        body.push(b'\n');
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let avail = &body[off..];
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        Ok(n)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
}

/// `/proc/self/status` per `19§4`. Synthesises body at read time
/// from the current task; bash and many libc fns parse this.
pub struct ProcSelfStatusInode;

impl ProcSelfStatusInode {
    fn body() -> alloc::vec::Vec<u8> {
        use core::sync::atomic::Ordering;
        let mut out = alloc::vec::Vec::with_capacity(256);
        let cur = crate::sched::current();
        let tid    = cur.map(|c| c.tid as u64).unwrap_or(1);
        let ppid   = cur.map(|c| c.parent_tid.load(Ordering::Acquire) as u64).unwrap_or(0);
        let name   = cur.map(|c| c.name).unwrap_or("oxide");
        push(&mut out, b"Name:\t");        push(&mut out, name.as_bytes()); push(&mut out, b"\n");
        push(&mut out, b"State:\tR (running)\n");
        push(&mut out, b"Tgid:\t");        push_u64(&mut out, tid); push(&mut out, b"\n");
        push(&mut out, b"Pid:\t");         push_u64(&mut out, tid); push(&mut out, b"\n");
        push(&mut out, b"PPid:\t");        push_u64(&mut out, ppid); push(&mut out, b"\n");
        push(&mut out, b"Uid:\t0\t0\t0\t0\n");
        push(&mut out, b"Gid:\t0\t0\t0\t0\n");
        push(&mut out, b"Threads:\t1\n");
        out
    }
}

impl Inode for ProcSelfStatusInode {
    fn ino(&self) -> Ino { 0x3000_1000 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let body = Self::body();
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let avail = &body[off..];
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        Ok(n)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
}

fn push(v: &mut alloc::vec::Vec<u8>, s: &[u8]) { v.extend_from_slice(s); }
fn push_u64(v: &mut alloc::vec::Vec<u8>, mut n: u64) {
    if n == 0 { v.push(b'0'); return; }
    let mut buf = [0u8; 20]; let mut i = 0;
    while n > 0 { buf[i] = b'0' + (n % 10) as u8; n /= 10; i += 1; }
    while i > 0 { i -= 1; v.push(buf[i]); }
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
    crate::devfs::register("/proc/self/status",  Arc::new(ProcSelfStatusInode)  as InodeRef);
    crate::devfs::register("/proc/self/cmdline", Arc::new(ProcSelfCmdlineInode) as InodeRef);
    crate::devfs::register("/proc/self/stat",    Arc::new(ProcSelfStatInode)    as InodeRef);
    crate::devfs::register("/proc/self/maps",    Arc::new(ProcSelfMapsInode)    as InodeRef);

    // /sys hierarchy (P3-19). Same Static inode shape; libc/systemd
    // probes look these up before falling back.
    crate::devfs::register("/sys/kernel/osrelease",
        StaticFileInode::new(b"0.1.0-pre\n") as InodeRef);
    crate::devfs::register("/sys/kernel/ostype",
        StaticFileInode::new(b"oxide\n") as InodeRef);
    crate::devfs::register("/sys/kernel/random/uuid",
        StaticFileInode::new(b"00000000-0000-0000-0000-000000000001\n") as InodeRef);
    crate::devfs::register("/sys/kernel/random/boot_id",
        StaticFileInode::new(b"00000000-0000-0000-0000-000000000002\n") as InodeRef);
    crate::devfs::register("/sys/kernel/random/entropy_avail",
        StaticFileInode::new(b"4096\n") as InodeRef);
    crate::devfs::register("/sys/devices/system/cpu/online",
        StaticFileInode::new(b"0\n") as InodeRef);
    crate::devfs::register("/sys/devices/system/cpu/possible",
        StaticFileInode::new(b"0\n") as InodeRef);
    crate::devfs::register("/etc/os-release",
        StaticFileInode::new(b"NAME=oxide\nID=oxide\nVERSION=\"0.1.0-pre\"\n") as InodeRef);
    crate::devfs::register("/etc/machine-id",
        StaticFileInode::new(b"00000000000000000000000000000001\n") as InodeRef);
    crate::devfs::register("/etc/hostname",
        StaticFileInode::new(b"oxide\n") as InodeRef);
    crate::devfs::register("/etc/passwd",
        StaticFileInode::new(b"root:x:0:0:root:/:/bin/sh\n") as InodeRef);
    crate::devfs::register("/etc/group",
        StaticFileInode::new(b"root:x:0:\n") as InodeRef);
    crate::devfs::register("/etc/nsswitch.conf",
        StaticFileInode::new(b"passwd: files\ngroup: files\nhosts: files\n") as InodeRef);
    crate::devfs::register("/etc/resolv.conf",
        StaticFileInode::new(b"") as InodeRef);
    crate::devfs::register("/etc/localtime",
        StaticFileInode::new(b"") as InodeRef);
    crate::devfs::register("/proc/self/oom_score",
        StaticFileInode::new(b"0\n") as InodeRef);
    crate::devfs::register("/proc/self/oom_score_adj",
        StaticFileInode::new(b"0\n") as InodeRef);
    crate::devfs::register("/proc/sys/kernel/random/boot_id",
        StaticFileInode::new(b"00000000-0000-0000-0000-000000000002\n") as InodeRef);
    crate::devfs::register("/proc/sys/kernel/pid_max",
        StaticFileInode::new(b"32768\n") as InodeRef);
    crate::devfs::register("/proc/sys/kernel/random/uuid",
        StaticFileInode::new(b"00000000-0000-0000-0000-000000000001\n") as InodeRef);
    crate::devfs::register("/proc/sys/kernel/ngroups_max",
        StaticFileInode::new(b"65536\n") as InodeRef);
    crate::devfs::register("/proc/sys/kernel/cap_last_cap",
        StaticFileInode::new(b"40\n") as InodeRef);
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
        ("/sys/kernel/random/uuid",  b"00000000"),
        ("/sys/kernel/random/boot_id", b"00000000"),
        ("/etc/os-release",          b"NAME=oxide"),
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
