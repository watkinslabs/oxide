//! `/proc/self/*` + system pseudo-files (maps, cmdline, stat, status,
//! environ, hostname, loadavg, meminfo, uptime, comm, fd). Split from
//! `live.rs` to keep both under the 1000-line cap; re-exported via `live`.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};
use crate::StaticFileInode;
use super::NEXT_INO;
/// `/proc/self/maps` per `19§4`. Walks the current task's
/// AddressSpace VMA tree and emits one line per VMA in
/// `<start>-<end> <perms> <off> 00:00 <ino> <path>` form. v1
/// path/offset/inode are stubs.
pub struct ProcSelfMapsInode;

impl ProcSelfMapsInode {
    fn body() -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::with_capacity(1024);
        let cur = match sched::live::current() {
            Some(c) => c,
            None => return out,
        };
        // SAFETY: running task on this CPU; preempt-off; sole reader of the mm slot per the single-mutator invariant in `13§5`.
        let mm = match unsafe { cur.mm_ref() } {
            Some(m) => m.clone(),
            None => return out,
        };
        let brk_lo = mm.brk_max().saturating_sub(0);
        let brk_hi = mm.brk();
        let _ = brk_lo;
        for vma in mm.snapshot_vmas() {
            push_hex(&mut out, vma.start.as_u64());
            out.push(b'-');
            push_hex(&mut out, vma.end.as_u64());
            out.push(b' ');
            // perms: rwx + p/s (private/shared) per Linux man page.
            let p = vma.prot;
            out.push(if p.contains(vmm::VmaProt::READ) {
                b'r'
            } else {
                b'-'
            });
            out.push(if p.contains(vmm::VmaProt::WRITE) {
                b'w'
            } else {
                b'-'
            });
            out.push(if p.contains(vmm::VmaProt::EXEC) {
                b'x'
            } else {
                b'-'
            });
            out.push(if vma.flags.contains(vmm::VmaFlags::SHARED) {
                b's'
            } else {
                b'p'
            });
            push(&mut out, b" 00000000 00:00 0 ");
            // F158: synthesise pathname pseudo-tags Linux emits for
            // unnamed VMAs. [stack] for GROWSDOWN; [heap] for the
            // anon VMA covering the current brk range.
            if vma.flags.contains(vmm::VmaFlags::GROWSDOWN) {
                push(&mut out, b"[stack]");
            } else if vma.start.as_u64() <= brk_hi
                && vma.end.as_u64() > 0
                && brk_hi > 0
                && vma.end.as_u64() > brk_hi.saturating_sub(0x10000)
                && matches!(vma.backing, vmm::VmaBacking::Anonymous)
            {
                push(&mut out, b"[heap]");
            }
            out.push(b'\n');
        }
        out
    }
}

impl Inode for ProcSelfMapsInode {
    fn ino(&self) -> Ino {
        0x3000_1300
    }
    fn file_type(&self) -> FileType {
        FileType::Regular
    }
    fn size(&self) -> u64 {
        0
    }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> {
        Err(VfsError::Enotdir)
    }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let body = Self::body();
        let off = off as usize;
        if off >= body.len() {
            return Ok(0);
        }
        let avail = &body[off..];
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        Ok(n)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> {
        Err(VfsError::Erofs)
    }
}

/// Append `n` as lowercase hex (no `0x`) to `v`. Shared by the self/ + pid maps inodes.
/// # C: O(hex digits)
pub(crate) fn push_hex(v: &mut alloc::vec::Vec<u8>, mut n: u64) {
    if n == 0 {
        v.push(b'0');
        return;
    }
    let mut buf = [0u8; 16];
    let mut i = 0;
    while n > 0 {
        let nib = (n & 0xf) as u8;
        buf[i] = if nib < 10 {
            b'0' + nib
        } else {
            b'a' + (nib - 10)
        };
        n >>= 4;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        v.push(buf[i]);
    }
}

/// `/proc/self/cmdline` per `19§4`. Reads `Task.cmdline` snapshot
/// (NUL-joined argv from the most recent execve). Falls back to
/// `Task.name` + NUL when no execve has run yet.
pub struct ProcSelfCmdlineInode;

impl Inode for ProcSelfCmdlineInode {
    fn ino(&self) -> Ino {
        0x3000_1100
    }
    fn file_type(&self) -> FileType {
        FileType::Regular
    }
    fn size(&self) -> u64 {
        0
    }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> {
        Err(VfsError::Enotdir)
    }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let mut body = alloc::vec::Vec::with_capacity(64);
        let cur = sched::live::current();
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
        if off >= body.len() {
            return Ok(0);
        }
        let avail = &body[off..];
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        Ok(n)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> {
        Err(VfsError::Erofs)
    }
}

/// `/proc/self/stat` per `19§4` — single space-separated line of
/// fields. v1: pid, comm in parens, state R, ppid, then zeros to
/// pad to the canonical 52 fields.
pub struct ProcSelfStatInode;

impl Inode for ProcSelfStatInode {
    fn ino(&self) -> Ino {
        0x3000_1200
    }
    fn file_type(&self) -> FileType {
        FileType::Regular
    }
    fn size(&self) -> u64 {
        0
    }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> {
        Err(VfsError::Enotdir)
    }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let mut body = alloc::vec::Vec::with_capacity(192);
        let cur = sched::live::current();
        // /proc/self/stat reports the VPID userspace sees (Linux field 1),
        // not the opaque internal tid; PPid likewise resolves to the parent's
        // vpid (mirrors pid_stat.rs; self fast-path used to leak internal tids).
        let vpid = cur.map(|c| sched::live::registry::display_vpid(c.tid)).unwrap_or(1);
        let ppid = cur.map(|c| sched::live::registry::parent_vpid(c.tid)).unwrap_or(0);
        let name = cur.map(|c| c.name).unwrap_or("init");
        push_u64(&mut body, vpid);
        push(&mut body, b" (");
        push(&mut body, name.as_bytes());
        let state_char = cur.map(|c| c.state().linux_char()).unwrap_or(b'R');
        push(&mut body, b") ");
        body.push(state_char);
        body.push(b' ');
        push_u64(&mut body, ppid);
        // pad with zeros to fill enough fields for libc parsers.
        for _ in 0..48 {
            push(&mut body, b" 0");
        }
        body.push(b'\n');
        let off = off as usize;
        if off >= body.len() {
            return Ok(0);
        }
        let avail = &body[off..];
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        Ok(n)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> {
        Err(VfsError::Erofs)
    }
}

/// `/proc/self/status` per `19§4`. Synthesises body at read time
/// from the current task; bash and many libc fns parse this.
pub struct ProcSelfStatusInode;

impl ProcSelfStatusInode {
    fn body() -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::with_capacity(256);
        let cur = sched::live::current();
        // VPID userspace sees (Tgid/Pid), and the parent's vpid (PPid) — not
        // the opaque internal tids the self fast-path used to leak.
        let tid = cur.map(|c| sched::live::registry::display_vpid(c.tid)).unwrap_or(1);
        let ppid = cur.map(|c| sched::live::registry::parent_vpid(c.tid)).unwrap_or(0);
        let name = cur.map(|c| c.name).unwrap_or("oxide");
        push(&mut out, b"Name:\t");
        push(&mut out, name.as_bytes());
        push(&mut out, b"\n");
        let state_label = cur
            .map(|c| c.state().linux_status_label())
            .unwrap_or("R (running)");
        push(&mut out, b"State:\t");
        push(&mut out, state_label.as_bytes());
        push(&mut out, b"\n");
        push(&mut out, b"Tgid:\t");
        push_u64(&mut out, tid);
        push(&mut out, b"\nPid:\t");
        push_u64(&mut out, tid);
        push(&mut out, b"\nPPid:\t");
        push_u64(&mut out, ppid);
        push(&mut out, b"\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n");
        push(&mut out, b"FDSize:\t");
        let fds = cur
            // SAFETY: fd_table slot single-mutator per `13§5`; current task is the running task on this CPU and the sole writer.
            .and_then(|c| unsafe { (*c.fd_table.get()).as_ref().cloned() })
            .map(|t| t.count() as u64)
            .unwrap_or(0);
        push_u64(&mut out, fds);
        push(&mut out, b"\n");
        push(&mut out, b"Groups:\t\n");
        let (vm, d, s, e, l) = cur
            // SAFETY: mm slot single-mutator per `13§5`; sole writer is this running task per the address-space ownership rule.
            .and_then(|c| unsafe {
                (*c.mm.get()).as_ref().map(|m| {
                    let (mut v, mut d, mut s, mut e, mut l) = (0u64, 0u64, 0u64, 0u64, 0u64);
                    for x in m.snapshot_vmas() {
                        let kb = (x.end.as_u64() - x.start.as_u64()) / 1024;
                        v += kb;
                        if x.flags.contains(vmm::VmaFlags::GROWSDOWN) {
                            s += kb;
                        } else if x.prot.contains(vmm::VmaProt::EXEC) {
                            e += kb;
                        } else if x.prot.contains(vmm::VmaProt::WRITE) {
                            d += kb;
                        } else {
                            l += kb;
                        }
                    }
                    (v, d, s, e, l)
                })
            })
            .unwrap_or((0, 0, 0, 0, 0));
        let row = |out: &mut alloc::vec::Vec<u8>, k: &[u8], v: u64| {
            push(out, k);
            push_u64(out, v);
            push(out, b" kB\n");
        };
        for &(k, v) in &[
            (b"VmPeak:\t" as &[u8], vm),
            (b"VmSize:\t", vm),
            (b"VmHWM:\t", vm),
            (b"VmRSS:\t", vm),
            (b"VmData:\t", d),
            (b"VmStk:\t", s),
            (b"VmExe:\t", e),
            (b"VmLib:\t", l),
        ] {
            row(&mut out, k, v);
        }
        push(&mut out, STATUS_TAIL);
        out
    }
}

const STATUS_TAIL: &[u8] = b"\
Threads:\t1\n\
SigQ:\t0/0\n\
SigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\n\
SigBlk:\t0000000000000000\nSigIgn:\t0000000000000000\nSigCgt:\t0000000000000000\n\
CapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\n\
CapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\n\
Cpus_allowed:\t1\nCpus_allowed_list:\t0\n\
Mems_allowed:\t1\nMems_allowed_list:\t0\n";

impl Inode for ProcSelfStatusInode {
    fn ino(&self) -> Ino {
        0x3000_1000
    }
    fn file_type(&self) -> FileType {
        FileType::Regular
    }
    fn size(&self) -> u64 {
        0
    }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> {
        Err(VfsError::Enotdir)
    }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let body = Self::body();
        let off = off as usize;
        if off >= body.len() {
            return Ok(0);
        }
        let avail = &body[off..];
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        Ok(n)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> {
        Err(VfsError::Erofs)
    }
}

/// # C: O(len s)
pub(crate) fn push(v: &mut alloc::vec::Vec<u8>, s: &[u8]) {
    v.extend_from_slice(s);
}
/// # C: O(log10 n)
pub(crate) fn push_u64(v: &mut alloc::vec::Vec<u8>, mut n: u64) {
    if n == 0 {
        v.push(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        v.push(buf[i]);
    }
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

// Canonical static bodies retained for documentation; live impls
// build dynamic versions above.
pub(crate) const FILESYSTEMS:  &[u8] = b"nodev\tsysfs\nnodev\tproc\nnodev\tdevtmpfs\nnodev\ttmpfs\nnodev\tdevpts\nnodev\tcgroup\nnodev\tcgroup2\nnodev\tpipefs\nnodev\tsockfs\nnodev\tbpf\nnodev\tmqueue\nnodev\trpc_pipefs\n\text4\n\text2\n\text3\n\tiso9660\n\tvfat\n\tmsdos\n\tfuseblk\n";
// /proc/mounts + /proc/<pid>/mountinfo are now generated dynamically
// from the live `vfs::mount` table — see `crate::mounts`.
pub(crate) const IO_BODY:      &[u8] = b"rchar: 0\nwchar: 0\nsyscr: 0\nsyscw: 0\nread_bytes: 0\nwrite_bytes: 0\ncancelled_write_bytes: 0\n";
pub(crate) const LIMITS_BODY: &[u8] = b"\
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
    fn ino(&self) -> Ino {
        0x3000_1800
    }
    fn file_type(&self) -> FileType {
        FileType::Regular
    }
    fn size(&self) -> u64 {
        0
    }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> {
        Err(VfsError::Enotdir)
    }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let cur = sched::live::current();
        // SAFETY: environ slot single-mutator per `13§5`.
        let snap = cur.and_then(|c| unsafe { (*c.environ.get()).clone() });
        let body: &[u8] = match snap.as_ref() {
            Some(s) => s.as_bytes(),
            None => &[],
        };
        let off = off as usize;
        if off >= body.len() {
            return Ok(0);
        }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body[off..off + n]);
        Ok(n)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> {
        Err(VfsError::Erofs)
    }
}

/// `/proc/sys/kernel/hostname` per Linux sysctl convention.
/// Reads the live `hostname` slot + trailing newline; writes
/// (echo "newhost" > /proc/sys/kernel/hostname) update the slot.
pub struct ProcHostnameInode;

impl Inode for ProcHostnameInode {
    fn ino(&self) -> Ino {
        0x3000_1C00
    }
    fn file_type(&self) -> FileType {
        FileType::Regular
    }
    fn size(&self) -> u64 {
        0
    }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> {
        Err(VfsError::Enotdir)
    }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let mut body = crate::hooks::hostname();
        body.push(b'\n');
        let off = off as usize;
        if off >= body.len() {
            return Ok(0);
        }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body[off..off + n]);
        Ok(n)
    }
    fn write(&self, _off: u64, src: &[u8]) -> KResult<usize> {
        crate::hooks::set_hostname(src);
        Ok(src.len())
    }
}

/// `/proc/loadavg` per `19§4`. "<1m> <5m> <15m> <run>/<total> <last_pid>\n".
/// Load averages are the real 1/5/15-min EWMA (`sched::loadavg`); run/total +
/// last_pid come from the live task registry.
pub struct ProcLoadavgInode;

impl Inode for ProcLoadavgInode {
    fn ino(&self) -> Ino {
        0x3000_1B00
    }
    fn file_type(&self) -> FileType {
        FileType::Regular
    }
    fn size(&self) -> u64 {
        0
    }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> {
        Err(VfsError::Enotdir)
    }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let mut body = alloc::vec::Vec::with_capacity(64);
        // B118: loadavg's last field is last_pid — a Linux PID, so it must
        // come from VPID space (live_vpids, sorted) not the opaque internal
        // tid. total = live task count (either list has the same length).
        let vpids = sched::live::registry::live_vpids();
        let total = vpids.len() as u64;
        let last = vpids.last().copied().unwrap_or(1) as u64;
        let (_, running) = sched::live::registry::live_counts();
        let avg = sched::loadavg::snapshot();
        for a in avg {
            let (i, f) = sched::loadavg::fmt_parts(a);
            push_u64(&mut body, i);
            body.push(b'.');
            if f < 10 { body.push(b'0'); }
            push_u64(&mut body, f);
            body.push(b' ');
        }
        push_u64(&mut body, running);
        body.push(b'/');
        push_u64(&mut body, total);
        body.push(b' ');
        push_u64(&mut body, last);
        body.push(b'\n');
        let off = off as usize;
        if off >= body.len() {
            return Ok(0);
        }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body[off..off + n]);
        Ok(n)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> {
        Err(VfsError::Erofs)
    }
}

/// `/proc/meminfo` per `19§4`. Reports MemTotal / MemFree / MemAvailable
/// from the live PMM allocator state in kB.
pub struct ProcMeminfoInode;

impl Inode for ProcMeminfoInode {
    fn ino(&self) -> Ino {
        0x3000_1A00
    }
    fn file_type(&self) -> FileType {
        FileType::Regular
    }
    fn size(&self) -> u64 {
        0
    }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> {
        Err(VfsError::Enotdir)
    }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let body = crate::meminfo::build();
        let off = off as usize;
        if off >= body.len() {
            return Ok(0);
        }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body[off..off + n]);
        Ok(n)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> {
        Err(VfsError::Erofs)
    }
}

fn pmm_kb_stats() -> (u64, u64) {
    match pmm::setup::pmm_static() {
        Some(p) => {
            let free = p.free_pages() * 4; // 4 KiB pages
            let alloc = p.allocated_pages() * 4;
            (free, alloc)
        }
        None => (0, 0),
    }
}

/// `/proc/uptime` per `19§4`. "<seconds.cs> <idle_seconds.cs>\n".
/// First field = monotonic clock; second = summed per-CPU idle time
/// from `sched::cpustat` (CLK_TCK=100 → 1 idle tick = 1 centisecond),
/// matching Linux where idle is the all-CPU sum (can exceed uptime).
pub struct ProcUptimeInode;

impl Inode for ProcUptimeInode {
    fn ino(&self) -> Ino {
        0x3000_1900
    }
    fn file_type(&self) -> FileType {
        FileType::Regular
    }
    fn size(&self) -> u64 {
        0
    }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> {
        Err(VfsError::Enotdir)
    }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let mut body = alloc::vec::Vec::with_capacity(48);
        let ns = uptime_ns();
        push_uptime(&mut body, ns);
        body.push(b' ');
        // idle: all-CPU summed idle centiseconds → ns for push_uptime.
        let idle_cs = sched::cpustat::snapshot().2;
        push_uptime(&mut body, idle_cs.saturating_mul(10_000_000));
        body.push(b'\n');
        let off = off as usize;
        if off >= body.len() {
            return Ok(0);
        }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body[off..off + n]);
        Ok(n)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> {
        Err(VfsError::Erofs)
    }
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
    let cs = total_cs % 100;
    push_u64(out, secs);
    out.push(b'.');
    if cs < 10 {
        out.push(b'0');
    }
    push_u64(out, cs);
}

/// `/proc/self/comm` per `19§4`. Reads `current().name` plus a
/// trailing newline. Real Linux also lets userspace `write()` it
/// to rename the thread; v1 is read-only.
pub struct ProcSelfCommInode;

impl Inode for ProcSelfCommInode {
    fn ino(&self) -> Ino {
        0x3000_1700
    }
    fn file_type(&self) -> FileType {
        FileType::Regular
    }
    fn size(&self) -> u64 {
        0
    }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> {
        Err(VfsError::Enotdir)
    }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let mut body = alloc::vec::Vec::with_capacity(32);
        let name = sched::live::current().map(|c| c.name).unwrap_or("oxide");
        push(&mut body, name.as_bytes());
        body.push(b'\n');
        let off = off as usize;
        if off >= body.len() {
            return Ok(0);
        }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body[off..off + n]);
        Ok(n)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> {
        Err(VfsError::Erofs)
    }
}

pub use crate::cmdline::ProcCmdlineInode;

/// `/proc/self/fd` directory. Walks `current().fd_table` and emits
/// each live fd as a decimal name. lookup(name) parses the fd back
/// and returns a placeholder inode mirroring the underlying File.
pub struct ProcSelfFdInode;

impl Inode for ProcSelfFdInode {
    fn ino(&self) -> Ino {
        0x3000_1500
    }
    fn file_type(&self) -> FileType {
        FileType::Directory
    }
    fn size(&self) -> u64 {
        0
    }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        let fd: i32 = name.parse().map_err(|_| VfsError::Enoent)?;
        let cur = sched::live::current().ok_or(VfsError::Enoent)?;
        // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
        let fdt = unsafe { cur.fd_table_ref() }
            .ok_or(VfsError::Enoent)?
            .clone();
        let file = fdt.get(fd).map_err(|_| VfsError::Enoent)?;
        // Linux: /proc/<pid>/fd/<n> readlink → file's ABSOLUTE path
        // (ttyname requires /dev/pts/<n>, not the basename "<n>").
        Ok(crate::proc_links::fd_link_for_path(
            &file.dentry().absolute_path(),
            fd,
        ))
    }
    fn readdir(&self, off: u64, f: &mut dyn FnMut(u64, &str, FileType) -> bool) -> KResult<u64> {
        let cur = match sched::live::current() {
            Some(c) => c,
            None => return Ok(off),
        };
        // SAFETY: sole reader; single-mutator per `13§5`.
        let fdt = match unsafe { cur.fd_table_ref() } {
            Some(t) => t.clone(),
            None => return Ok(off),
        };
        let fds = fdt.live_fds();
        let mut idx = off as usize;
        while idx < fds.len() {
            let next = idx as u64 + 1;
            let fd = fds[idx];
            let mut buf = [0u8; 11];
            let mut n = 0;
            let mut t = fd as u32;
            if t == 0 {
                buf[0] = b'0';
                n = 1;
            } else {
                while t > 0 {
                    buf[n] = b'0' + (t % 10) as u8;
                    t /= 10;
                    n += 1;
                }
            }
            buf[..n].reverse();
            let s = core::str::from_utf8(&buf[..n]).unwrap_or("0");
            if !f(next, s, FileType::Symlink) {
                return Ok(next);
            }
            idx += 1;
        }
        Ok(idx as u64)
    }
    fn read(&self, _o: u64, _b: &mut [u8]) -> KResult<usize> {
        Err(VfsError::Eisdir)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> {
        Err(VfsError::Erofs)
    }
}

/// `/proc` root directory inode. readdir emits live tids (decimal
/// names) plus `self`. lookup parses tids and returns a per-pid dir.
pub use crate::proc_links::{
    ProcFdLinkInode, ProcSelfCwdInode, ProcSelfExeInode, ProcSelfRootInode,
};

