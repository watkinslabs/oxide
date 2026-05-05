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

const VERSION_BODY: &[u8] = b"Linux version 5.15.0-oxide (oxide@build) #1 SMP PREEMPT\n";

#[cfg(target_arch = "x86_64")]
const CPUINFO_BODY: &[u8] = b"\
processor\t: 0\n\
vendor_id\t: GenuineIntel\n\
cpu family\t: 6\n\
model\t\t: 158\n\
model name\t: Oxide CPU @ 2.00GHz\n\
stepping\t: 0\n\
cpu MHz\t\t: 2000.000\n\
cache size\t: 8192 KB\n\
physical id\t: 0\n\
siblings\t: 1\n\
core id\t\t: 0\n\
cpu cores\t: 1\n\
apicid\t\t: 0\n\
fpu\t\t: yes\n\
fpu_exception\t: yes\n\
cpuid level\t: 13\n\
wp\t\t: yes\n\
flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx lm constant_tsc rep_good nopl cpuid tsc_known_freq pni pclmulqdq ssse3 cx16 sse4_1 sse4_2 popcnt aes xsave avx f16c rdrand hypervisor lahf_lm cmp_legacy abm sse4a misalignsse 3dnowprefetch xsaveopt arat\n\
bogomips\t: 4000.00\n\
clflush size\t: 64\n\
cache_alignment\t: 64\n\
address sizes\t: 39 bits physical, 48 bits virtual\n\
power management:\n\
\n";
#[cfg(target_arch = "aarch64")]
const CPUINFO_BODY: &[u8] = b"\
processor\t: 0\n\
BogoMIPS\t: 100.00\n\
Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop\n\
CPU implementer\t: 0x41\n\
CPU architecture: 8\n\
CPU variant\t: 0x0\n\
CPU part\t: 0xd03\n\
CPU revision\t: 4\n\
\n";

const MEMINFO_BODY: &[u8] = b"MemTotal:        65536 kB\nMemFree:         32768 kB\nMemAvailable:    32768 kB\n";
const UPTIME_BODY:  &[u8] = b"0.00 0.00\n";
const LOADAVG_BODY: &[u8] = b"0.00 0.00 0.00 1/1 1\n";
const STAT_BODY:    &[u8] = b"cpu  0 0 0 0 0 0 0 0 0 0\n";
const FILESYSTEMS:  &[u8] = b"nodev\tdevtmpfs\nnodev\tprocfs\n";
const MOUNTS_BODY:  &[u8] = b"devtmpfs /dev devtmpfs rw 0 0\nprocfs /proc procfs rw 0 0\n";
const MOUNTINFO_BODY: &[u8] = b"1 0 0:1 / / rw - rootfs rootfs rw\n2 1 0:2 / /dev rw - devtmpfs devtmpfs rw\n3 1 0:3 / /proc rw - proc proc rw\n4 1 0:4 / /tmp rw - tmpfs tmpfs rw\n";
const IO_BODY:      &[u8] = b"rchar: 0\nwchar: 0\nsyscr: 0\nsyscw: 0\nread_bytes: 0\nwrite_bytes: 0\ncancelled_write_bytes: 0\n";
const LIMITS_BODY:  &[u8] = b"\
Limit                     Soft Limit           Hard Limit           Units\n\
Max cpu time              unlimited            unlimited            seconds\n\
Max file size             unlimited            unlimited            bytes\n\
Max data size             unlimited            unlimited            bytes\n\
Max stack size            8388608              unlimited            bytes\n\
Max core file size        0                    unlimited            bytes\n\
Max resident set          unlimited            unlimited            bytes\n\
Max processes             unlimited            unlimited            processes\n\
Max open files            1024                 4096                 files\n\
Max locked memory         65536                65536                bytes\n\
Max address space         unlimited            unlimited            bytes\n\
Max file locks            unlimited            unlimited            locks\n\
Max pending signals       unlimited            unlimited            signals\n\
Max msgqueue size         819200               819200               bytes\n\
Max nice priority         0                    0                    \n\
Max realtime priority     0                    0                    \n\
Max realtime timeout      unlimited            unlimited            us\n";

/// `/proc/self/environ` per `19§4`. Reads the NUL-joined envp
/// snapshot taken at execve. Empty for tasks with no execve.
pub struct ProcSelfEnvironInode;

impl Inode for ProcSelfEnvironInode {
    fn ino(&self) -> Ino { 0x3000_1800 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let cur = crate::sched::current();
        // SAFETY: environ slot single-mutator per `13§5`.
        let snap = cur.and_then(|c| unsafe { (*c.environ.get()).clone() });
        let body: &[u8] = match snap.as_ref() { Some(s) => s.as_bytes(), None => &[] };
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body[off..off + n]);
        Ok(n)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
}

/// `/proc/sys/kernel/hostname` per Linux sysctl convention.
/// Reads the live `hostname` slot + trailing newline; writes
/// (echo "newhost" > /proc/sys/kernel/hostname) update the slot.
pub struct ProcHostnameInode;

impl Inode for ProcHostnameInode {
    fn ino(&self) -> Ino { 0x3000_1C00 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let mut body = crate::hostname::snapshot();
        body.push(b'\n');
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body[off..off + n]);
        Ok(n)
    }
    fn write(&self, _off: u64, src: &[u8]) -> KResult<usize> {
        crate::hostname::set(src);
        Ok(src.len())
    }
}

/// `/proc/loadavg` per `19§4`. "<1m> <5m> <15m> <run>/<total> <last_pid>\n".
/// v1: load averages are 0.00 (no decay accounting yet); run/total
/// pulls live tids from the registry; last_pid reports the same.
pub struct ProcLoadavgInode;

impl Inode for ProcLoadavgInode {
    fn ino(&self) -> Ino { 0x3000_1B00 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let mut body = alloc::vec::Vec::with_capacity(64);
        let tids = crate::sched::registry::live_tids();
        let total = tids.len() as u64;
        let last = tids.last().copied().unwrap_or(1) as u64;
        push(&mut body, b"0.00 0.00 0.00 ");
        push_u64(&mut body, total); body.push(b'/');
        push_u64(&mut body, total); body.push(b' ');
        push_u64(&mut body, last); body.push(b'\n');
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body[off..off + n]);
        Ok(n)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
}

/// `/proc/meminfo` per `19§4`. Reports MemTotal / MemFree / MemAvailable
/// from the live PMM allocator state in kB.
pub struct ProcMeminfoInode;

impl Inode for ProcMeminfoInode {
    fn ino(&self) -> Ino { 0x3000_1A00 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let mut body = alloc::vec::Vec::with_capacity(192);
        let (free_kb, alloc_kb) = pmm_kb_stats();
        let total_kb = free_kb + alloc_kb;
        push(&mut body, b"MemTotal:        "); push_u64(&mut body, total_kb); push(&mut body, b" kB\n");
        push(&mut body, b"MemFree:         "); push_u64(&mut body, free_kb);  push(&mut body, b" kB\n");
        push(&mut body, b"MemAvailable:    "); push_u64(&mut body, free_kb);  push(&mut body, b" kB\n");
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body[off..off + n]);
        Ok(n)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
}

fn pmm_kb_stats() -> (u64, u64) {
    match crate::pmm_setup::pmm_static() {
        Some(p) => {
            let free  = p.free_pages() * 4; // 4 KiB pages
            let alloc = p.allocated_pages() * 4;
            (free, alloc)
        }
        None => (0, 0),
    }
}

/// `/proc/uptime` per `19§4`. "<seconds.cs> <idle_seconds.cs>\n".
/// Reports the kernel's monotonic clock in seconds; idle is the
/// same value (v1 has no separate idle accounting yet).
pub struct ProcUptimeInode;

impl Inode for ProcUptimeInode {
    fn ino(&self) -> Ino { 0x3000_1900 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let mut body = alloc::vec::Vec::with_capacity(48);
        let ns = uptime_ns();
        push_uptime(&mut body, ns); body.push(b' ');
        push_uptime(&mut body, ns); body.push(b'\n');
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body[off..off + n]);
        Ok(n)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
}

#[cfg(target_arch = "x86_64")]
fn uptime_ns() -> u64 {
    use hal::TimerOps;
    hal_x86_64::X86TimerOps::monotonic_ns().0
}
#[cfg(target_arch = "aarch64")]
fn uptime_ns() -> u64 {
    use hal::TimerOps;
    hal_aarch64::ArmTimerOps::monotonic_ns().0
}

fn push_uptime(out: &mut alloc::vec::Vec<u8>, ns: u64) {
    let total_cs = ns / 10_000_000;
    let secs = total_cs / 100;
    let cs   = total_cs % 100;
    push_u64(out, secs);
    out.push(b'.');
    if cs < 10 { out.push(b'0'); }
    push_u64(out, cs);
}

/// `/proc/self/comm` per `19§4`. Reads `current().name` plus a
/// trailing newline. Real Linux also lets userspace `write()` it
/// to rename the thread; v1 is read-only.
pub struct ProcSelfCommInode;

impl Inode for ProcSelfCommInode {
    fn ino(&self) -> Ino { 0x3000_1700 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let mut body = alloc::vec::Vec::with_capacity(32);
        let name = crate::sched::current().map(|c| c.name).unwrap_or("oxide");
        push(&mut body, name.as_bytes());
        body.push(b'\n');
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body[off..off + n]);
        Ok(n)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
}

/// `/proc/self/fd` directory. Walks `current().fd_table` and emits
/// each live fd as a decimal name. lookup(name) parses the fd back
/// and returns a placeholder inode mirroring the underlying File.
pub struct ProcSelfFdInode;

impl Inode for ProcSelfFdInode {
    fn ino(&self) -> Ino { 0x3000_1500 }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        let fd: i32 = name.parse().map_err(|_| VfsError::Enoent)?;
        let cur = crate::sched::current().ok_or(VfsError::Enoent)?;
        // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
        let fdt = unsafe { cur.fd_table_ref() }.ok_or(VfsError::Enoent)?.clone();
        fdt.get(fd).map(|f| f.inode().clone()).map_err(|_| VfsError::Enoent)
    }
    fn readdir(
        &self,
        off: u64,
        f: &mut dyn FnMut(u64, &str, FileType) -> bool,
    ) -> KResult<u64> {
        let cur = match crate::sched::current() { Some(c) => c, None => return Ok(off) };
        // SAFETY: sole reader; single-mutator per `13§5`.
        let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return Ok(off) };
        let fds = fdt.live_fds();
        let mut idx = off as usize;
        while idx < fds.len() {
            let next = idx as u64 + 1;
            let fd = fds[idx];
            let mut buf = [0u8; 11];
            let mut n = 0; let mut t = fd as u32;
            if t == 0 { buf[0] = b'0'; n = 1; }
            else { while t > 0 { buf[n] = b'0' + (t % 10) as u8; t /= 10; n += 1; } }
            buf[..n].reverse();
            let s = core::str::from_utf8(&buf[..n]).unwrap_or("0");
            if !f(next, s, FileType::Symlink) { return Ok(next); }
            idx += 1;
        }
        Ok(idx as u64)
    }
    fn read(&self, _o: u64, _b: &mut [u8]) -> KResult<usize> { Err(VfsError::Eisdir) }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
}

/// `/proc` root directory inode. readdir emits live tids (decimal
/// names) plus `self`. lookup parses tids and returns a per-pid dir.
pub struct ProcRootInode;

impl Inode for ProcRootInode {
    fn ino(&self) -> Ino { 0x3000_0001 }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        if name == "self" {
            // /proc/self resolves via existing devfs entries; the dir
            // marker itself is synthetic — return a directory inode.
            return Ok(Arc::new(ProcPidDirInode { tid: 0, is_self: true }) as InodeRef);
        }
        match name.parse::<u32>() {
            Ok(tid) if crate::sched::registry::lookup(tid).is_some() =>
                Ok(Arc::new(ProcPidDirInode { tid, is_self: false }) as InodeRef),
            _ => Err(VfsError::Enoent),
        }
    }
    fn readdir(
        &self,
        off: u64,
        f: &mut dyn FnMut(u64, &str, FileType) -> bool,
    ) -> KResult<u64> {
        let mut idx = off as usize;
        let tids = crate::sched::registry::live_tids();
        let total = tids.len() + 1; // +1 for "self"
        while idx < total {
            let next = idx as u64 + 1;
            if idx == 0 {
                if !f(next, "self", FileType::Directory) { return Ok(next); }
            } else {
                let tid = tids[idx - 1];
                let mut buf = [0u8; 11];
                let mut n = 0; let mut t = tid;
                if t == 0 { buf[0] = b'0'; n = 1; }
                else { while t > 0 { buf[n] = b'0' + (t % 10) as u8; t /= 10; n += 1; } }
                buf[..n].reverse();
                let s = core::str::from_utf8(&buf[..n]).unwrap_or("0");
                if !f(next, s, FileType::Directory) { return Ok(next); }
            }
            idx += 1;
        }
        Ok(idx as u64)
    }
}

/// Per-pid `/proc/<tid>` directory. Synthesises status/cmdline/stat/maps.
pub struct ProcPidDirInode { pub tid: u32, pub is_self: bool }

impl Inode for ProcPidDirInode {
    fn ino(&self) -> Ino { 0x3000_0100 | self.tid as Ino }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        if self.is_self {
            // Delegate to existing /proc/self/<name> entries.
            let mut p = alloc::string::String::with_capacity(11 + name.len());
            p.push_str("/proc/self/");
            p.push_str(name);
            return crate::devfs::lookup(&p).ok_or(VfsError::Enoent);
        }
        match name {
            "status"  => Ok(Arc::new(ProcPidStatusInode  { tid: self.tid }) as InodeRef),
            "cmdline" => Ok(Arc::new(ProcPidCmdlineInode { tid: self.tid }) as InodeRef),
            "stat"    => Ok(Arc::new(ProcPidStatInode    { tid: self.tid }) as InodeRef),
            "maps"    => Ok(Arc::new(ProcPidMapsInode    { tid: self.tid }) as InodeRef),
            "comm"    => Ok(Arc::new(ProcPidCommInode    { tid: self.tid }) as InodeRef),
            "environ" => Ok(Arc::new(ProcPidEnvironInode { tid: self.tid }) as InodeRef),
            "statm"   => Ok(Arc::new(ProcPidStatmInode   { tid: self.tid }) as InodeRef),
            "wchan"   => Ok(StaticFileInode::new(b"0") as InodeRef),
            "oom_score" => Ok(StaticFileInode::new(b"0\n") as InodeRef),
            "oom_score_adj" => Ok(StaticFileInode::new(b"0\n") as InodeRef),
            "loginuid" => Ok(StaticFileInode::new(b"0\n") as InodeRef),
            "sessionid" => Ok(StaticFileInode::new(b"0\n") as InodeRef),
            "io"       => Ok(StaticFileInode::new(b"rchar: 0\nwchar: 0\nsyscr: 0\nsyscw: 0\n") as InodeRef),
            "limits"   => Ok(StaticFileInode::new(LIMITS_BODY) as InodeRef),
            "personality" => Ok(StaticFileInode::new(b"00000000\n") as InodeRef),
            "sched"   => Ok(Arc::new(ProcPidSchedInode { tid: self.tid }) as InodeRef),
            "schedstat" => Ok(StaticFileInode::new(b"0 0 0\n") as InodeRef),
            "autogroup" => Ok(StaticFileInode::new(b"/autogroup-1 nice 0\n") as InodeRef),
            _         => Err(VfsError::Enoent),
        }
    }
    fn readdir(
        &self,
        off: u64,
        f: &mut dyn FnMut(u64, &str, FileType) -> bool,
    ) -> KResult<u64> {
        const ENTRIES: &[&str] = &[
            "status", "cmdline", "stat", "maps", "comm", "environ", "statm",
            "wchan", "oom_score", "oom_score_adj", "loginuid", "sessionid",
            "io", "limits", "personality", "sched", "schedstat", "autogroup",
        ];
        let mut idx = off as usize;
        while idx < ENTRIES.len() {
            let next = idx as u64 + 1;
            if !f(next, ENTRIES[idx], FileType::Regular) { return Ok(next); }
            idx += 1;
        }
        Ok(idx as u64)
    }
}

/// Per-pid status. Body mirrors `ProcSelfStatusInode` but resolves
/// the target via `sched::registry::lookup(tid)`.
pub struct ProcPidStatusInode { pub tid: u32 }
pub struct ProcPidCmdlineInode { pub tid: u32 }
pub struct ProcPidStatInode { pub tid: u32 }
pub struct ProcPidMapsInode { pub tid: u32 }
pub struct ProcPidCommInode { pub tid: u32 }
pub struct ProcPidEnvironInode { pub tid: u32 }
pub struct ProcPidStatmInode { pub tid: u32 }
pub struct ProcPidSchedInode { pub tid: u32 }

fn pid_status_body(tid: u32) -> alloc::vec::Vec<u8> {
    use core::sync::atomic::Ordering;
    let mut out = alloc::vec::Vec::with_capacity(256);
    let task = match crate::sched::registry::lookup(tid) { Some(t) => t, None => return out };
    let ppid = task.parent_tid.load(Ordering::Acquire) as u64;
    push(&mut out, b"Name:\t"); push(&mut out, task.name.as_bytes()); push(&mut out, b"\n");
    push(&mut out, b"State:\tR (running)\n");
    push(&mut out, b"Tgid:\t"); push_u64(&mut out, tid as u64); push(&mut out, b"\n");
    push(&mut out, b"Pid:\t");  push_u64(&mut out, tid as u64); push(&mut out, b"\n");
    push(&mut out, b"PPid:\t"); push_u64(&mut out, ppid); push(&mut out, b"\n");
    push(&mut out, b"Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nThreads:\t1\n");
    out
}

fn pid_cmdline_body(tid: u32) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(64);
    let task = match crate::sched::registry::lookup(tid) { Some(t) => t, None => return out };
    // SAFETY: snapshot of cmdline slot; written only by the task itself per `13§5`.
    let snap = unsafe { (*task.cmdline.get()).clone() };
    if let Some(s) = snap { push(&mut out, s.as_bytes()); }
    else { push(&mut out, task.name.as_bytes()); out.push(0); }
    out
}

fn pid_stat_body(tid: u32) -> alloc::vec::Vec<u8> {
    use core::sync::atomic::Ordering;
    let mut out = alloc::vec::Vec::with_capacity(192);
    let task = match crate::sched::registry::lookup(tid) { Some(t) => t, None => return out };
    let ppid = task.parent_tid.load(Ordering::Acquire) as u64;
    push_u64(&mut out, tid as u64);
    push(&mut out, b" ("); push(&mut out, task.name.as_bytes()); push(&mut out, b") R ");
    push_u64(&mut out, ppid);
    for _ in 0..48 { push(&mut out, b" 0"); }
    out.push(b'\n');
    out
}

fn pid_maps_body(tid: u32) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(1024);
    let task = match crate::sched::registry::lookup(tid) { Some(t) => t, None => return out };
    // SAFETY: mm slot read-only borrow; single-mutator per `13§5`.
    let mm = match unsafe { (*task.mm.get()).as_ref() } { Some(m) => m.clone(), None => return out };
    for vma in mm.snapshot_vmas() {
        push_hex(&mut out, vma.start.as_u64());
        out.push(b'-');
        push_hex(&mut out, vma.end.as_u64());
        out.push(b' ');
        let p = vma.prot;
        out.push(if p.contains(vmm::VmaProt::READ)  { b'r' } else { b'-' });
        out.push(if p.contains(vmm::VmaProt::WRITE) { b'w' } else { b'-' });
        out.push(if p.contains(vmm::VmaProt::EXEC)  { b'x' } else { b'-' });
        out.push(b'p');
        push(&mut out, b" 00000000 00:00 0 \n");
    }
    out
}

macro_rules! pid_inode_impl {
    ($t:ident, $body:ident, $ino:expr) => {
        impl Inode for $t {
            fn ino(&self) -> Ino { $ino | self.tid as Ino }
            fn file_type(&self) -> FileType { FileType::Regular }
            fn size(&self) -> u64 { 0 }
            fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
            fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
                let body = $body(self.tid);
                let off = off as usize;
                if off >= body.len() { return Ok(0); }
                let n = (body.len() - off).min(buf.len());
                buf[..n].copy_from_slice(&body[off..off + n]);
                Ok(n)
            }
            fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
        }
    };
}

pid_inode_impl!(ProcPidStatusInode,  pid_status_body,  0x3000_2000);
pid_inode_impl!(ProcPidCmdlineInode, pid_cmdline_body, 0x3000_2100);
pid_inode_impl!(ProcPidStatInode,    pid_stat_body,    0x3000_2200);
pid_inode_impl!(ProcPidMapsInode,    pid_maps_body,    0x3000_2300);
pid_inode_impl!(ProcPidCommInode,    pid_comm_body,    0x3000_2400);
pid_inode_impl!(ProcPidEnvironInode, pid_environ_body, 0x3000_2500);
pid_inode_impl!(ProcPidStatmInode,   pid_statm_body,   0x3000_2600);
pid_inode_impl!(ProcPidSchedInode,   pid_sched_body,   0x3000_2700);

fn pid_sched_body(tid: u32) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(128);
    let task = match crate::sched::registry::lookup(tid) { Some(t) => t, None => return out };
    push(&mut out, task.name.as_bytes());
    push(&mut out, b" (");
    push_u64(&mut out, tid as u64);
    push(&mut out, b", #threads: 1)\n");
    push(&mut out, b"-------------------------------------------------------------------\n");
    push(&mut out, b"se.exec_start                                :         0.000000\n");
    push(&mut out, b"se.vruntime                                  :         0.000000\n");
    push(&mut out, b"se.sum_exec_runtime                          :         0.000000\n");
    push(&mut out, b"nr_switches                                  :                0\n");
    push(&mut out, b"prio                                         :              120\n");
    push(&mut out, b"policy                                       :                0\n");
    out
}

fn pid_statm_body(tid: u32) -> alloc::vec::Vec<u8> {
    // statm fields (in pages of 4 KiB): size resident shared text lib data dt
    // v1: report total VMA range as size + resident; others 0.
    let mut out = alloc::vec::Vec::with_capacity(48);
    let task = match crate::sched::registry::lookup(tid) { Some(t) => t, None => return out };
    // SAFETY: mm slot single-mutator per `13§5`.
    let pages = match unsafe { (*task.mm.get()).as_ref() } {
        Some(mm) => mm.snapshot_vmas().iter()
            .map(|v| (v.end.as_u64() - v.start.as_u64()) / 4096)
            .sum::<u64>(),
        None => 0,
    };
    push_u64(&mut out, pages); out.push(b' ');
    push_u64(&mut out, pages); out.push(b' ');
    push(&mut out, b"0 0 0 0 0\n");
    out
}

fn pid_comm_body(tid: u32) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(32);
    let task = match crate::sched::registry::lookup(tid) { Some(t) => t, None => return out };
    push(&mut out, task.name.as_bytes());
    out.push(b'\n');
    out
}

fn pid_environ_body(tid: u32) -> alloc::vec::Vec<u8> {
    let task = match crate::sched::registry::lookup(tid) {
        Some(t) => t, None => return alloc::vec::Vec::new(),
    };
    // SAFETY: environ slot single-mutator per `13§5`.
    match unsafe { (*task.environ.get()).clone() } {
        Some(s) => s.into_bytes(),
        None    => alloc::vec::Vec::new(),
    }
}

/// Resolve dynamic `/proc/<tid>[/<file>]` paths. Returns `None` for
/// non-procfs paths; callers fall back to the static devfs registry.
/// Path-shape parsing lives in `crates/procfs::paths` (hosted-tested).
/// # C: O(N_tasks)
pub fn lookup_dynamic(path: &str) -> Option<InodeRef> {
    use procfs::paths::{parse_proc_path, ProcPath};
    match parse_proc_path(path) {
        ProcPath::SelfDir =>
            Some(Arc::new(ProcPidDirInode { tid: 0, is_self: true }) as InodeRef),
        ProcPath::SelfChild(_) => None, // /proc/self/<file> served by devfs
        ProcPath::PidDir(tid) => {
            if crate::sched::registry::lookup(tid).is_none() { return None; }
            Some(Arc::new(ProcPidDirInode { tid, is_self: false }) as InodeRef)
        }
        ProcPath::PidChild(tid, leaf) => {
            if crate::sched::registry::lookup(tid).is_none() { return None; }
            match leaf {
                "status"  => Some(Arc::new(ProcPidStatusInode  { tid }) as InodeRef),
                "cmdline" => Some(Arc::new(ProcPidCmdlineInode { tid }) as InodeRef),
                "stat"    => Some(Arc::new(ProcPidStatInode    { tid }) as InodeRef),
                "maps"    => Some(Arc::new(ProcPidMapsInode    { tid }) as InodeRef),
                _ => None,
            }
        }
        ProcPath::NotProc => None,
    }
}

/// Register the v1 procfs entries into devfs.
/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(N_files)
pub fn init() {
    crate::devfs::register("/proc/version",     StaticFileInode::new(VERSION_BODY)     as InodeRef);
    crate::devfs::register("/proc/cpuinfo",     StaticFileInode::new(CPUINFO_BODY)     as InodeRef);
    crate::devfs::register("/proc/meminfo",     Arc::new(ProcMeminfoInode)             as InodeRef);
    crate::devfs::register("/proc/uptime",      Arc::new(ProcUptimeInode)              as InodeRef);
    crate::devfs::register("/proc/loadavg",     Arc::new(ProcLoadavgInode)             as InodeRef);
    crate::devfs::register("/proc/stat",        StaticFileInode::new(STAT_BODY)        as InodeRef);
    crate::devfs::register("/proc/filesystems", StaticFileInode::new(FILESYSTEMS)      as InodeRef);
    crate::devfs::register("/proc/cmdline",     StaticFileInode::new(b"BOOT_IMAGE=/oxide root=/dev/oxide0 ro quiet console=ttyS0\n") as InodeRef);
    crate::devfs::register("/proc/devices",     StaticFileInode::new(b"\
Character devices:\n  1 mem\n  4 /dev/vc/0\n  5 /dev/tty\n136 pts\nBlock devices:\n") as InodeRef);
    crate::devfs::register("/proc/modules",     StaticFileInode::new(b"") as InodeRef);
    crate::devfs::register("/proc/swaps",       StaticFileInode::new(b"Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n") as InodeRef);
    crate::devfs::register("/proc/diskstats",   StaticFileInode::new(b"") as InodeRef);
    crate::devfs::register("/proc/partitions",  StaticFileInode::new(b"major minor  #blocks  name\n") as InodeRef);
    crate::devfs::register("/proc/misc",        StaticFileInode::new(b"") as InodeRef);
    crate::devfs::register("/proc/buddyinfo",   StaticFileInode::new(b"Node 0, zone Normal      0 0 0 0 0 0 0 0 0 0 0\n") as InodeRef);
    crate::devfs::register("/proc/zoneinfo",    StaticFileInode::new(b"Node 0, zone Normal\n  pages free 1024\n") as InodeRef);
    crate::devfs::register("/proc/vmstat",      StaticFileInode::new(b"nr_free_pages 1024\nnr_zone_inactive_anon 0\nnr_zone_active_anon 0\n") as InodeRef);
    crate::devfs::register("/proc/interrupts",  StaticFileInode::new(b"           CPU0       \nLOC: 1234   Local timer interrupts\n") as InodeRef);
    crate::devfs::register("/proc/softirqs",    StaticFileInode::new(b"                CPU0       \n      HI:          0\n   TIMER:       1234\n") as InodeRef);
    crate::devfs::register("/proc/kallsyms",    StaticFileInode::new(b"") as InodeRef);
    crate::devfs::register("/proc/key-users",   StaticFileInode::new(b"") as InodeRef);
    crate::devfs::register("/proc/keys",        StaticFileInode::new(b"") as InodeRef);
    crate::devfs::register("/proc/locks",       StaticFileInode::new(b"") as InodeRef);
    crate::devfs::register("/proc/crypto",      StaticFileInode::new(b"") as InodeRef);
    crate::devfs::register("/proc/execdomains", StaticFileInode::new(b"0-0\tLinux           \t[kernel]\n") as InodeRef);
    crate::devfs::register("/proc/mounts",      StaticFileInode::new(MOUNTS_BODY)      as InodeRef);
    // /proc root inode for getdents64 enumeration of live tids.
    crate::devfs::register("/proc",              Arc::new(ProcRootInode)        as InodeRef);
    crate::devfs::register("/proc/self/status",  Arc::new(ProcSelfStatusInode)  as InodeRef);
    crate::devfs::register("/proc/self/cmdline", Arc::new(ProcSelfCmdlineInode) as InodeRef);
    crate::devfs::register("/proc/self/comm",    Arc::new(ProcSelfCommInode)    as InodeRef);
    crate::devfs::register("/proc/self/environ", Arc::new(ProcSelfEnvironInode) as InodeRef);
    crate::devfs::register("/proc/self/stat",    Arc::new(ProcSelfStatInode)    as InodeRef);
    crate::devfs::register("/proc/self/maps",    Arc::new(ProcSelfMapsInode)    as InodeRef);
    crate::devfs::register("/proc/self/fd",      Arc::new(ProcSelfFdInode)      as InodeRef);

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
    crate::devfs::register("/etc/shadow",
        StaticFileInode::new(b"root::0:0:99999:7:::\n") as InodeRef);
    crate::devfs::register("/etc/shells",
        StaticFileInode::new(b"/bin/sh\n") as InodeRef);
    crate::devfs::register("/etc/profile",
        StaticFileInode::new(b"export PATH=/bin:/usr/bin\nexport PS1='$ '\n") as InodeRef);
    crate::devfs::register("/etc/issue",
        StaticFileInode::new(b"oxide \\r \\l\n\n") as InodeRef);
    crate::devfs::register("/etc/motd",
        StaticFileInode::new(b"Welcome to oxide.\n") as InodeRef);
    crate::devfs::register("/etc/hosts",
        StaticFileInode::new(b"127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost\n") as InodeRef);
    crate::devfs::register("/etc/services",
        StaticFileInode::new(b"\
ssh\t\t22/tcp\nssh\t\t22/udp\n\
http\t\t80/tcp\nhttp\t\t80/udp\n\
https\t\t443/tcp\nhttps\t\t443/udp\n\
domain\t\t53/tcp\ndomain\t\t53/udp\n\
") as InodeRef);
    crate::devfs::register("/etc/protocols",
        StaticFileInode::new(b"\
ip\t0\tIP\nicmp\t1\tICMP\ntcp\t6\tTCP\nudp\t17\tUDP\n\
") as InodeRef);
    crate::devfs::register("/etc/ld.so.cache",
        StaticFileInode::new(b"") as InodeRef);
    crate::devfs::register("/etc/ld.so.conf",
        StaticFileInode::new(b"include /etc/ld.so.conf.d/*.conf\n") as InodeRef);
    crate::devfs::register("/etc/timezone",
        StaticFileInode::new(b"UTC\n") as InodeRef);
    crate::devfs::register("/proc/self/oom_score",
        StaticFileInode::new(b"0\n") as InodeRef);
    crate::devfs::register("/proc/self/oom_score_adj",
        StaticFileInode::new(b"0\n") as InodeRef);
    crate::devfs::register("/proc/self/limits",
        StaticFileInode::new(LIMITS_BODY) as InodeRef);
    crate::devfs::register("/proc/self/io",
        StaticFileInode::new(IO_BODY) as InodeRef);
    crate::devfs::register("/proc/self/mountinfo",
        StaticFileInode::new(MOUNTINFO_BODY) as InodeRef);
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
    crate::devfs::register("/proc/sys/kernel/osrelease",
        StaticFileInode::new(b"5.15.0-oxide\n") as InodeRef);
    crate::devfs::register("/proc/sys/kernel/ostype",
        StaticFileInode::new(b"Linux\n") as InodeRef);
    crate::devfs::register("/proc/sys/kernel/version",
        StaticFileInode::new(b"#1 SMP PREEMPT oxide v0.1.0\n") as InodeRef);
    crate::devfs::register("/proc/sys/kernel/hostname",
        Arc::new(ProcHostnameInode) as InodeRef);
    crate::devfs::register("/proc/sys/kernel/domainname",
        StaticFileInode::new(b"(none)\n") as InodeRef);
    crate::devfs::register("/proc/sys/kernel/threads-max",
        StaticFileInode::new(b"32768\n") as InodeRef);
    crate::devfs::register("/proc/sys/fs/file-max",
        StaticFileInode::new(b"65536\n") as InodeRef);
    crate::devfs::register("/proc/sys/fs/file-nr",
        StaticFileInode::new(b"0\t0\t65536\n") as InodeRef);
    crate::devfs::register("/proc/sys/fs/nr_open",
        StaticFileInode::new(b"1048576\n") as InodeRef);
    crate::devfs::register("/proc/sys/fs/inotify/max_user_watches",
        StaticFileInode::new(b"65536\n") as InodeRef);
    crate::devfs::register("/proc/sys/fs/inotify/max_user_instances",
        StaticFileInode::new(b"128\n") as InodeRef);
    crate::devfs::register("/proc/sys/fs/inotify/max_queued_events",
        StaticFileInode::new(b"16384\n") as InodeRef);
    crate::devfs::register("/proc/sys/fs/pipe-max-size",
        StaticFileInode::new(b"4096\n") as InodeRef);
    crate::devfs::register("/proc/sys/vm/overcommit_memory",
        StaticFileInode::new(b"0\n") as InodeRef);
    crate::devfs::register("/proc/sys/vm/swappiness",
        StaticFileInode::new(b"60\n") as InodeRef);
    crate::devfs::register("/proc/sys/net/core/somaxconn",
        StaticFileInode::new(b"4096\n") as InodeRef);
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
        ("/proc/version", b"Linux"),
        ("/proc/cpuinfo", b"processor"),
        ("/proc/meminfo", b"MemTotal:"),
        // /proc/uptime is dynamic now (P3-111) — skipped from smoke (its body is
        // a function of monotonic_ns, not a static prefix).
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
