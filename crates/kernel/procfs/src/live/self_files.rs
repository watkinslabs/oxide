//! `/proc/self/*` + system pseudo-files (maps, cmdline, stat, status,
//! environ, hostname, loadavg, meminfo, uptime, comm, fd). Split from
//! `live.rs` to keep both under the 1000-line cap; re-exported via `live`.
//!
//! KEYSTONE struct-`Inode` model: each leaf is a `vfs::Inode` built by a
//! `make_*` constructor over `dyn_file` (read-only generators) or a bespoke
//! `FileOps` (hostname is writable; `/proc/self/fd` is a synthetic dir).

use alloc::sync::Arc;
use alloc::vec::Vec;
use vfs::{default_inode_ops, mk_mode, DirContext, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

const HOSTNAME_FILE_MODE: u16 = 0o644;
const SELF_FD_DIR_MODE: u16 = 0o555;

/// `/proc/self/maps` per `19§4`. Walks the current task's AddressSpace VMA
/// tree and emits one line per VMA in `<start>-<end> <perms> <off> 00:00
/// <ino> <path>` form. v1 path/offset/inode are stubs.
fn maps_body() -> Vec<u8> {
    let mut out = Vec::with_capacity(1024);
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
        out.push(if p.contains(vmm::VmaProt::READ) { b'r' } else { b'-' });
        out.push(if p.contains(vmm::VmaProt::WRITE) { b'w' } else { b'-' });
        out.push(if p.contains(vmm::VmaProt::EXEC) { b'x' } else { b'-' });
        out.push(if vma.flags.contains(vmm::VmaFlags::SHARED) { b's' } else { b'p' });
        push(&mut out, b" 00000000 00:00 0 ");
        // F158: synthesise pathname pseudo-tags Linux emits for unnamed VMAs.
        // [stack] for GROWSDOWN; [heap] for the anon VMA covering brk.
        if vma.flags.contains(vmm::VmaFlags::GROWSDOWN) {
            push(&mut out, b"[stack]");
        } else if let Some(name) = vma.anon_name.as_ref() {
            push(&mut out, b"[anon:");
            push(&mut out, name.as_bytes());
            push(&mut out, b"]");
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

/// `/proc/self/maps` inode. # C: O(1)
pub fn make_proc_self_maps() -> InodeRef { crate::dyn_file::make_gen_file(crate::ids::SELF_MAPS, maps_body) }

/// Append `n` as lowercase hex (no `0x`) to `v`. Shared by the self/ + pid maps inodes.
/// # C: O(hex digits)
pub(crate) fn push_hex(v: &mut Vec<u8>, mut n: u64) {
    if n == 0 {
        v.push(b'0');
        return;
    }
    let mut buf = [0u8; 16];
    let mut i = 0;
    while n > 0 {
        let nib = (n & 0xf) as u8;
        buf[i] = if nib < 10 { b'0' + nib } else { b'a' + (nib - 10) };
        n >>= 4;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        v.push(buf[i]);
    }
}

/// `/proc/self/cmdline` per `19§4`. Reads `Task.cmdline` snapshot (NUL-joined
/// argv from the most recent execve). Falls back to `Task.name` + NUL.
fn self_cmdline_body() -> Vec<u8> {
    let mut body = Vec::with_capacity(64);
    let cur = sched::live::current();
    // SAFETY: single-mutator per `13§5`; current task is the sole writer to
    // its own cmdline slot, and we are it on this CPU.
    let snapshot = cur.and_then(|c| c.cmdline());
    if let Some(s) = snapshot {
        push(&mut body, s.as_bytes());
    } else {
        let name = cur.map(|c| c.comm()).unwrap_or_else(|| alloc::string::String::from("init"));
        push(&mut body, name.as_bytes());
        body.push(0);
    }
    body
}
/// `/proc/self/cmdline` inode. # C: O(1)
pub fn make_proc_self_cmdline() -> InodeRef { crate::dyn_file::make_gen_file(crate::ids::SELF_CMDLINE, self_cmdline_body) }

/// `/proc/self/stat` per `19§4` — single space-separated line of fields. v1:
/// pid, comm in parens, state R, ppid, then zeros to pad to ~52 fields.
fn self_stat_body() -> Vec<u8> {
    let mut body = Vec::with_capacity(192);
    let cur = sched::live::current();
    // /proc/self/stat reports the VPID userspace sees (Linux field 1), not the
    // opaque internal tid; PPid likewise resolves to the parent's vpid.
    let vpid = cur.map(|c| sched::live::registry::display_vpid(c.tid)).unwrap_or(1);
    let ppid = cur.map(|c| sched::live::registry::parent_vpid(c.tid)).unwrap_or(0);
    let name = cur.map(|c| c.comm()).unwrap_or_else(|| alloc::string::String::from("init"));
    let starttime = cur.map(|c| crate::proc_clock::ReaderClock::current()
        .starttime_ticks(c.start_boottime_ns)).unwrap_or(0);
    push_u64(&mut body, vpid);
    push(&mut body, b" (");
    push(&mut body, name.as_bytes());
    let state_char = cur.map(|c| c.state().linux_char()).unwrap_or(b'R');
    push(&mut body, b") ");
    body.push(state_char);
    body.push(b' ');
    push_u64(&mut body, ppid);
    // Fields 5..52; starttime is Linux field 22.
    for field in 5..=52 {
        push(&mut body, b" ");
        push_u64(&mut body, if field == 22 { starttime } else { 0 });
    }
    body.push(b'\n');
    body
}
/// `/proc/self/stat` inode. # C: O(1)
pub fn make_proc_self_stat() -> InodeRef { crate::dyn_file::make_gen_file(crate::ids::SELF_STAT, self_stat_body) }

/// `/proc/self/status` — the SAME renderer `/proc/<pid>/status` uses, run
/// against the current task. This file used to be a SECOND, independent
/// renderer carrying its own `Uid:\t0\t0\t0\t0` / `CapPrm = 000001ffffffffff`
/// constants and its own `Threads`/`Sig*`/`Cpus_allowed` tail, so the two
/// paths could — and did — disagree about the same task's credentials. It also
/// reported `VmRSS` as the total MAPPED size, which is not RSS; the shared
/// renderer sources the whole `Vm*`/`Rss*` block from the per-mm resident-page
/// counters instead, so this file, `/proc/<pid>/statm` and `ru_maxrss` cannot
/// disagree. # C: as `pid_status::body`
fn self_status_body() -> Vec<u8> {
    match sched::live::current() {
        Some(c) => crate::pid_status::body(c.tid),
        None    => Vec::new(),
    }
}
/// `/proc/self/status` inode. # C: O(1)
pub fn make_proc_self_status() -> InodeRef { crate::dyn_file::make_gen_file(crate::ids::SELF_STATUS, self_status_body) }


/// # C: O(len s)
pub(crate) fn push(v: &mut Vec<u8>, s: &[u8]) {
    v.extend_from_slice(s);
}
/// # C: O(log10 n)
pub(crate) fn push_u64(v: &mut Vec<u8>, mut n: u64) {
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

// /proc/cpuinfo is generated per-online-CPU from CPUID / MIDR_EL1 — see
// `crate::cpuinfo`. The two hardcoded single-block blobs that used to live
// here were a SPLIT SOURCE OF TRUTH against that generator and hid every AP
// behind `processor : 0`; nothing has registered them since.

// /proc/filesystems is generated from the live `vfs::fs` type registry —
// see `crate::filesystems`. The hardcoded blob that used to live here was a
// SPLIT SOURCE OF TRUTH against that registry and against `sysfs(2)`, which
// indexes the same list: it advertised `cgroup`, `pipefs`, `sockfs`,
// `rpc_pipefs`, `ext2`, `ext3`, `iso9660`, `vfat`, `msdos`, `fuseblk` — none
// registered, so every mount of one failed after the probe said yes — and
// omitted `ramfs`, `debugfs`, `tracefs`, `securityfs`, `efivarfs`, `pstore`,
// `configfs`, `fusectl`, `hugetlbfs`, `fuse`, which do exist.
// /proc/mounts + /proc/<pid>/mountinfo are now generated dynamically
// from the live `vfs::mount` table — see `crate::mounts`.

/// `/proc/self/environ` per `19§4`. Reads the NUL-joined envp snapshot taken
/// at execve. Empty for tasks with no execve.
fn self_environ_body() -> Vec<u8> {
    let cur = sched::live::current();
    // SAFETY: environ slot single-mutator per `13§5`.
    let snap = cur.and_then(|c| c.environ());
    match snap {
        Some(s) => s.into_bytes(),
        None => Vec::new(),
    }
}
/// `/proc/self/environ` inode. # C: O(1)
pub fn make_proc_self_environ() -> InodeRef { crate::dyn_file::make_gen_file(crate::ids::SELF_ENVIRON, self_environ_body) }

/// `i_fop` for `/proc/sys/kernel/hostname` — read the live hostname slot +
/// trailing newline; write updates the slot.
struct HostnameFileOps;
impl FileOps for HostnameFileOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn read(&self, _inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let mut body = crate::hooks::hostname();
        body.push(b'\n');
        Ok(crate::dyn_file::read_at(&body, off, buf))
    }
    fn write(&self, _inode: &Inode, _off: u64, src: &[u8]) -> KResult<usize> {
        crate::hooks::set_hostname(src);
        Ok(src.len())
    }
}
/// `/proc/sys/kernel/hostname` inode (writable). # C: O(1)
pub fn make_proc_hostname() -> InodeRef {
    InodeBuilder::new(crate::ids::HOSTNAME, mk_mode(FileType::Regular, HOSTNAME_FILE_MODE), default_inode_ops(), Arc::new(HostnameFileOps))
        .build()
}

/// `/proc/loadavg` per `19§4`. "<1m> <5m> <15m> <run>/<total> <last_pid>\n".
fn loadavg_body() -> Vec<u8> {
    let mut body = Vec::with_capacity(64);
    // B118: loadavg's last field is last_pid — a Linux PID, so it must come
    // from VPID space (live_vpids, sorted). total = live task count.
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
    body
}
/// `/proc/loadavg` inode. # C: O(1)
pub fn make_proc_loadavg() -> InodeRef { crate::dyn_file::make_gen_file(crate::ids::LOADAVG, loadavg_body) }

/// `/proc/meminfo` inode. # C: O(1)
pub fn make_proc_meminfo() -> InodeRef { crate::dyn_file::make_gen_file(crate::ids::MEMINFO, crate::meminfo::build) }

/// `/proc/uptime` per `19§4`. "<seconds.cs> <idle_seconds.cs>\n".
fn uptime_body() -> Vec<u8> {
    let mut body = Vec::with_capacity(48);
    let idle_ns = sched::cpustat::snapshot().2.saturating_mul(10_000_000);
    let (ns, idle_ns) = crate::proc_clock::ReaderClock::current().uptime(uptime_ns(), idle_ns);
    push_uptime(&mut body, ns);
    body.push(b' ');
    // idle remains the global all-CPU summed duration.
    push_uptime(&mut body, idle_ns);
    body.push(b'\n');
    body
}
/// `/proc/uptime` inode. # C: O(1)
pub fn make_proc_uptime() -> InodeRef { crate::dyn_file::make_gen_file(crate::ids::UPTIME, uptime_body) }

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

fn push_uptime(out: &mut Vec<u8>, ns: u64) {
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

/// `/proc/self/comm` per `19§4`. Reads `current().comm()` (the canonical,
/// prctl(PR_SET_NAME)-mutable field, `B1414`) plus a trailing newline.
fn self_comm_body() -> Vec<u8> {
    let mut body = Vec::with_capacity(32);
    let name = sched::live::current().map(|c| c.comm()).unwrap_or_else(|| alloc::string::String::from("oxide"));
    push(&mut body, name.as_bytes());
    body.push(b'\n');
    body
}
/// `/proc/self/comm` inode. # C: O(1)
pub fn make_proc_self_comm() -> InodeRef { crate::dyn_file::make_gen_file(crate::ids::SELF_COMM, self_comm_body) }

pub use crate::cmdline::make_proc_cmdline;

/// Resolve a child of `/proc/<tid_opt>/fd` (a decimal fd → magic symlink).
/// `tid_opt` = `None` for `/proc/self/fd` (caller's table), `Some(tid)` for a
/// specific pid — so the link resolves against the TARGET's fd table.
fn fd_lookup_for(tid_opt: Option<u32>, name: &str) -> KResult<InodeRef> {
    let fd: i32 = name.parse().map_err(|_| VfsError::Enoent)?;
    let file = sched::proclink::proc_fd_file(tid_opt, fd).ok_or(VfsError::Enoent)?;
    // Linux: /proc/<pid>/fd/<n> readlink → file's ABSOLUTE path (ttyname needs
    // /dev/pts/<n>). A walk THROUGH the magic link jumps to the target's live fd.
    Ok(crate::proc_links::fd_link_for_path(
        &file.dentry().absolute_path(),
        tid_opt,
        fd,
    ))
}

/// `i_op`/`i_fop` for `/proc/<tid>/fd` — lookup parses the fd, readdir walks the
/// TARGET task's live fd table (`tid = None` ⇒ caller's own, for `/proc/self`).
struct ProcSelfFdOps { tid: Option<u32> }
impl InodeOps for ProcSelfFdOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> { fd_lookup_for(self.tid, name) }
}
impl FileOps for ProcSelfFdOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn iterate(&self, _inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let fds = sched::proclink::proc_fd_list(self.tid);
        let mut idx = ctx.pos as usize;
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
            let s = crate::util::decimal_str(&buf, n);
            let ino = fd_lookup_for(self.tid, s).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(s, ino, FileType::Symlink, next) {
                return Ok(());
            }
            idx += 1;
        }
        Ok(())
    }
}

/// `/proc/self/fd` directory inode (caller's own fd table). # C: O(1)
pub fn make_proc_self_fd() -> InodeRef { make_proc_fd_dir(None) }

/// `/proc/<tid>/fd` directory inode listing the TARGET task's fds.
/// `tid = None` ⇒ `/proc/self/fd` (caller's own). # C: O(1)
pub fn make_proc_fd_dir(tid: Option<u32>) -> InodeRef {
    InodeBuilder::new(crate::ids::SELF_FD_DIR, mk_mode(FileType::Directory, SELF_FD_DIR_MODE),
        Arc::new(ProcSelfFdOps { tid }), Arc::new(ProcSelfFdOps { tid }))
        .build()
}

pub use crate::proc_links::{make_proc_self_cwd, make_proc_self_exe, make_proc_self_root};
