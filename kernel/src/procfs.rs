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
        let state_char = cur.map(|c| c.state().linux_char()).unwrap_or(b'R');
        push(&mut body, b") "); body.push(state_char); body.push(b' ');
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
        let state_label = cur.map(|c| c.state().linux_status_label()).unwrap_or("R (running)");
        push(&mut out, b"State:\t"); push(&mut out, state_label.as_bytes()); push(&mut out, b"\n");
        push(&mut out, b"Tgid:\t");        push_u64(&mut out, tid); push(&mut out, b"\n");
        push(&mut out, b"Pid:\t");         push_u64(&mut out, tid); push(&mut out, b"\n");
        push(&mut out, b"PPid:\t");        push_u64(&mut out, ppid); push(&mut out, b"\n");
        push(&mut out, b"Uid:\t0\t0\t0\t0\n");
        push(&mut out, b"Gid:\t0\t0\t0\t0\n");
        push(&mut out, b"FDSize:\t");
        // SAFETY: fd_table slot single-mutator per `13§5`; current task is the running task on this CPU and the sole writer.
        let fds = cur.and_then(|c| unsafe { (*c.fd_table.get()).as_ref().cloned() })
            .map(|t| t.count() as u64).unwrap_or(0);
        push_u64(&mut out, fds); push(&mut out, b"\n");
        push(&mut out, b"Groups:\t\n");
        // SAFETY: mm slot single-mutator per `13§5`; current task is the running task on this CPU and the sole writer.
        let vm_kb = cur.and_then(|c| unsafe { (*c.mm.get()).as_ref().map(|m| {
            m.snapshot_vmas().iter()
                .map(|v| (v.end.as_u64() - v.start.as_u64()) / 1024).sum::<u64>()
        })}).unwrap_or(0);
        push(&mut out, b"VmPeak:\t"); push_u64(&mut out, vm_kb); push(&mut out, b" kB\n");
        push(&mut out, b"VmSize:\t"); push_u64(&mut out, vm_kb); push(&mut out, b" kB\n");
        push(&mut out, b"VmRSS:\t");  push_u64(&mut out, vm_kb); push(&mut out, b" kB\n");
        push(&mut out, STATUS_TAIL);
        out
    }
}

const STATUS_TAIL: &[u8] = b"\
VmData:\t0 kB\nVmStk:\t8 kB\nVmExe:\t4 kB\nVmLib:\t0 kB\n\
Threads:\t1\n\
SigQ:\t0/0\n\
SigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\n\
SigBlk:\t0000000000000000\nSigIgn:\t0000000000000000\nSigCgt:\t0000000000000000\n\
CapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\n\
CapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\n\
Cpus_allowed:\t1\nCpus_allowed_list:\t0\n\
Mems_allowed:\t1\nMems_allowed_list:\t0\n";

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

pub(crate) const VERSION_BODY: &[u8] = b"Linux version 5.15.0-oxide (oxide@build) #1 SMP PREEMPT\n";

#[cfg(target_arch = "x86_64")]
pub(crate) const CPUINFO_BODY: &[u8] = b"\
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
pub(crate) const CPUINFO_BODY: &[u8] = b"\
processor\t: 0\n\
BogoMIPS\t: 100.00\n\
Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop\n\
CPU implementer\t: 0x41\n\
CPU architecture: 8\n\
CPU variant\t: 0x0\n\
CPU part\t: 0xd03\n\
CPU revision\t: 4\n\
\n";

// Static bodies — kept around as documentation of the canonical
// pseudo-format even though the live implementations now compute
// these dynamically.
#[allow(dead_code)]
const MEMINFO_BODY: &[u8] = b"MemTotal:        65536 kB\nMemFree:         32768 kB\nMemAvailable:    32768 kB\n";
#[allow(dead_code)]
const UPTIME_BODY:  &[u8] = b"0.00 0.00\n";
#[allow(dead_code)]
const LOADAVG_BODY: &[u8] = b"0.00 0.00 0.00 1/1 1\n";
pub(crate) const STAT_BODY:    &[u8] = b"\
cpu  0 0 0 0 0 0 0 0 0 0\n\
cpu0 0 0 0 0 0 0 0 0 0 0\n\
intr 0\n\
ctxt 0\n\
btime 0\n\
processes 1\n\
procs_running 1\n\
procs_blocked 0\n\
softirq 0 0 0 0 0 0 0 0 0 0\n";
pub(crate) const FILESYSTEMS:  &[u8] = b"nodev\tdevtmpfs\nnodev\tprocfs\n";
pub(crate) const MOUNTS_BODY:  &[u8] = b"\
devtmpfs /dev devtmpfs rw,nosuid,relatime 0 0\n\
procfs /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n\
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n\
tmpfs /tmp tmpfs rw,nosuid,nodev,relatime 0 0\n\
ext4 / ext4 rw,relatime 0 0\n";
pub(crate) const MOUNTINFO_BODY: &[u8] = b"1 0 0:1 / / rw - rootfs rootfs rw\n2 1 0:2 / /dev rw - devtmpfs devtmpfs rw\n3 1 0:3 / /proc rw - proc proc rw\n4 1 0:4 / /tmp rw - tmpfs tmpfs rw\n";
pub(crate) const IO_BODY:      &[u8] = b"rchar: 0\nwchar: 0\nsyscr: 0\nsyscw: 0\nread_bytes: 0\nwrite_bytes: 0\ncancelled_write_bytes: 0\n";
pub(crate) const LIMITS_BODY:  &[u8] = b"\
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
            "limits"   => Ok(Arc::new(ProcPidLimitsInode { tid: self.tid }) as InodeRef),
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
pub struct ProcPidLimitsInode { pub tid: u32 }
pub struct ProcPidSchedInode { pub tid: u32 }

fn pid_status_body(tid: u32) -> alloc::vec::Vec<u8> {
    use core::sync::atomic::Ordering;
    let mut out = alloc::vec::Vec::with_capacity(256);
    let task = match crate::sched::registry::lookup(tid) { Some(t) => t, None => return out };
    let ppid = task.parent_tid.load(Ordering::Acquire) as u64;
    push(&mut out, b"Name:\t"); push(&mut out, task.name.as_bytes()); push(&mut out, b"\n");
    push(&mut out, b"State:\t"); push(&mut out, task.state().linux_status_label().as_bytes()); push(&mut out, b"\n");
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
    push(&mut out, b" ("); push(&mut out, task.name.as_bytes()); push(&mut out, b") ");
    out.push(task.state().linux_char()); out.push(b' ');
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
pid_inode_impl!(ProcPidLimitsInode,  pid_limits_body,  0x3000_2800);

/// Render /proc/<pid>/limits from the live per-task rlimit slot.
fn pid_limits_body(tid: u32) -> alloc::vec::Vec<u8> {
    use sched::rlimit::{rlim, format_rlim};
    let mut out = alloc::vec::Vec::with_capacity(2048);
    let task = match crate::sched::registry::lookup(tid) {
        Some(t) => t, None => return out,
    };
    push(&mut out, b"Limit                     Soft Limit           Hard Limit           Units\n");
    let names: &[(usize, &[u8], &[u8])] = &[
        (rlim::CPU,        b"Max cpu time             ", b"seconds"),
        (rlim::FSIZE,      b"Max file size            ", b"bytes"),
        (rlim::DATA,       b"Max data size            ", b"bytes"),
        (rlim::STACK,      b"Max stack size           ", b"bytes"),
        (rlim::CORE,       b"Max core file size       ", b"bytes"),
        (rlim::RSS,        b"Max resident set         ", b"bytes"),
        (rlim::NPROC,      b"Max processes            ", b"processes"),
        (rlim::NOFILE,     b"Max open files           ", b"files"),
        (rlim::MEMLOCK,    b"Max locked memory        ", b"bytes"),
        (rlim::AS,         b"Max address space        ", b"bytes"),
        (rlim::LOCKS,      b"Max file locks           ", b"locks"),
        (rlim::SIGPENDING, b"Max pending signals      ", b"signals"),
        (rlim::MSGQUEUE,   b"Max msgqueue size        ", b"bytes"),
        (rlim::NICE,       b"Max nice priority        ", b""),
        (rlim::RTPRIO,     b"Max realtime priority    ", b""),
        (rlim::RTTIME,     b"Max realtime timeout     ", b"us"),
    ];
    // SAFETY: rlimits slot single-mutator per `13§5`; reading a snapshot.
    let limits = unsafe { *task.rlimits.get() };
    let mut buf = [0u8; 32];
    for (i, label, units) in names {
        push(&mut out, label);
        let n = format_rlim(&mut buf, limits[*i].0).unwrap_or(0);
        push(&mut out, &buf[..n]);
        for _ in n..21 { out.push(b' '); }
        let n = format_rlim(&mut buf, limits[*i].1).unwrap_or(0);
        push(&mut out, &buf[..n]);
        for _ in n..21 { out.push(b' '); }
        push(&mut out, units);
        out.push(b'\n');
    }
    out
}
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
        ProcPath::NotProc => {
            match path {
                "/proc/net/dev"  => Some(Arc::new(ProcNetDevInode)  as InodeRef),
                "/proc/net/tcp"  => Some(Arc::new(ProcNetTcpInode)  as InodeRef),
                "/proc/net/udp"  => Some(Arc::new(ProcNetUdpInode)  as InodeRef),
                "/proc/modules"  => Some(Arc::new(ProcModulesInode) as InodeRef),
                _ => None,
            }
        }
    }
}

/// `/proc/net/dev` — Linux text format: header + per-iface line.
struct ProcNetDevInode;
impl vfs::Inode for ProcNetDevInode {
    fn ino(&self) -> vfs::Ino { 0xFEED_0001 }
    fn file_type(&self) -> vfs::FileType { vfs::FileType::Regular }
    fn size(&self) -> u64 { self.body().len() as u64 }
    fn lookup(&self, _n: &str) -> vfs::KResult<vfs::InodeRef> { Err(vfs::VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        let body = self.body();
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body.as_bytes()[off..off+n]);
        Ok(n)
    }
}

impl ProcNetDevInode {
    fn body(&self) -> alloc::string::String {
        use alloc::string::String;
        use core::fmt::Write as _;
        let mut s = String::new();
        let _ = writeln!(s, "Inter-|   Receive                                                |  Transmit");
        let _ = writeln!(s, " face |bytes packets errs drop fifo frame compressed multicast |bytes packets errs drop fifo colls carrier compressed");
        let stack = crate::dev_net::stack();
        let snap = stack.ifaces.snapshot();
        for (id, name, mtu) in snap {
            let stats = stack.ifaces.lookup(id).map(|d| d.stats()).unwrap_or_default();
            let _ = writeln!(s, "{:>6}: {} {} {} {} 0 0 0 0 {} {} {} {} 0 0 0 0  # mtu={}",
                name,
                stats.rx_bytes, stats.rx_packets, stats.rx_errors, stats.rx_dropped,
                stats.tx_bytes, stats.tx_packets, stats.tx_errors, stats.tx_dropped,
                mtu);
        }
        s
    }
}

/// `/proc/net/tcp` — Linux fixed-width per-connection table.
struct ProcNetTcpInode;
impl vfs::Inode for ProcNetTcpInode {
    fn ino(&self) -> vfs::Ino { 0xFEED_0002 }
    fn file_type(&self) -> vfs::FileType { vfs::FileType::Regular }
    fn size(&self) -> u64 { self.body().len() as u64 }
    fn lookup(&self, _n: &str) -> vfs::KResult<vfs::InodeRef> { Err(vfs::VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        let body = self.body();
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body.as_bytes()[off..off+n]);
        Ok(n)
    }
}

impl ProcNetTcpInode {
    fn body(&self) -> alloc::string::String {
        // v1 surfaces just the header; per-connection rows ride
        // alongside a Stack::tcp_conns_snapshot() helper. The
        // shape lets `ss -t` parse without erroring on empty.
        alloc::string::String::from(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        )
    }
}

/// `/proc/net/udp` — UDP equivalent.
struct ProcNetUdpInode;
impl vfs::Inode for ProcNetUdpInode {
    fn ino(&self) -> vfs::Ino { 0xFEED_0003 }
    fn file_type(&self) -> vfs::FileType { vfs::FileType::Regular }
    fn size(&self) -> u64 { self.body().len() as u64 }
    fn lookup(&self, _n: &str) -> vfs::KResult<vfs::InodeRef> { Err(vfs::VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        let body = self.body();
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body.as_bytes()[off..off+n]);
        Ok(n)
    }
}

impl ProcNetUdpInode {
    fn body(&self) -> alloc::string::String {
        alloc::string::String::from(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n",
        )
    }
}

/// `/proc/modules` — Linux text format: "<name> <size> <refcnt> <holders> <state> <addr>\n".
/// v1 uses synthetic name "module_<idx>" since .modinfo parsing
/// hasn't landed.
struct ProcModulesInode;
impl vfs::Inode for ProcModulesInode {
    fn ino(&self) -> vfs::Ino { 0xFEED_0004 }
    fn file_type(&self) -> vfs::FileType { vfs::FileType::Regular }
    fn size(&self) -> u64 { self.body().len() as u64 }
    fn lookup(&self, _n: &str) -> vfs::KResult<vfs::InodeRef> { Err(vfs::VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        let body = self.body();
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body.as_bytes()[off..off+n]);
        Ok(n)
    }
}

impl ProcModulesInode {
    fn body(&self) -> alloc::string::String {
        use alloc::string::String;
        use core::fmt::Write as _;
        let mut s = String::new();
        for (idx, n_secs, n_syms) in crate::dev_modules::snapshot() {
            let _ = writeln!(s, "module_{} {} {} - Live 0x0 sec={} sym={}",
                idx, n_secs * 4096, 0, n_secs, n_syms);
        }
        s
    }
}

/// Register the v1 procfs entries (delegated to procfs_static).
/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(N_files)
pub fn init() { crate::procfs_static::register_static_files(); }

/// Boot-time smoke for the registered files.
/// # SAFETY: caller is the boot path; pre-init.
/// # C: O(N)
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
