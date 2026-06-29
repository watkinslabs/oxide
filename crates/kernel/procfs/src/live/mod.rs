//! Kernel-side procfs integration. Body builders live in
//! crates/kernel/procfs (target-clean); the kernel-side mounting
//! and per-pid wiring stays here.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use vfs::{default_file_ops, mk_mode, FileOps, FileType, Ino, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

pub static NEXT_INO: AtomicU64 = AtomicU64::new(0x3000_0000);

/// Collision-free per-pid / -tid / -fd procfs inode number (Linux
/// `proc_alloc_inum` analogue). The entry `tag` occupies bits [32,48) and the
/// pid/tid/fd the low 32 bits, so no `(tag, id)` pair can alias another the
/// way the old `tag | id` packing did once `id` set a bit inside `tag`'s
/// range (D24). High nibble `0x3` keeps it in procfs's inode space. # C: O(1)
pub(crate) fn pid_ino(tag: u64, id: u32) -> Ino {
    0x3000_0000_0000_0000 | (tag << 32) | id as u64
}

/// Static-body procfs file. `read(off, buf)` returns the window
/// `body[off..off+buf.len()]` clamped to body length.
use crate::StaticFileInode;

// `/proc/self/*` + system pseudo-files split out (1000-line cap, docs/08§7).
mod self_files;
pub use self_files::*;

/// The `/proc` root directory — a real directory inode that OWNS its static
/// children (the Linux `proc_dir_entry` `subdir` tree: cpuinfo/meminfo/stat/…),
/// built once at boot via `new()` (the `proc_create` equivalent) and immutable
/// thereafter. `self` and the per-pid `/proc/<pid>` dirs are synthesized, like
/// Linux. No flat string registry — lookup/readdir walk THIS directory's tree.
pub struct ProcRootInode {
    children: alloc::collections::BTreeMap<alloc::string::String, InodeRef>,
}

fn proc_root_lookup(d: &ProcRootInode, name: &str) -> KResult<InodeRef> {
    // The directory's own static children first (the subdir tree).
    if let Some(i) = d.children.get(name) { return Ok(i.clone()); }
    if name == "self" {
        return Ok(make_proc_pid_dir(0, true, true));
    }
    // procfs OWNS its `/proc/{sys,net,...}` subtrees as kernfs PseudoDirs
    // hung under PROC_REG (D1d) — the sysctl interface (kernel/domainname,
    // kernel/hostname, …), /proc/net, etc. Resolved through procfs's OWN
    // tree (chroot-INDEPENDENT, Linux proc_sys_lookup), no longer the
    // shared devfs registry. Must win over the numeric-PID parse below.
    if let Some(i) = crate::reg::proc_reg().lookup_path(name) { return Ok(i); }
    // `name` is a Linux PID (vtgid); translate via pid_to_kernel_tid.
    let vpid: u32 = name.parse().map_err(|_| VfsError::Enoent)?;
    let tid = pid_to_kernel_tid(vpid).ok_or(VfsError::Enoent)?;
    Ok(make_proc_pid_dir(tid, false, true))
}

struct ProcRootOps;
impl InodeOps for ProcRootOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<ProcRootInode>().ok_or(VfsError::Einval)?;
        proc_root_lookup(d, name)
    }
}
impl FileOps for ProcRootOps {
    fn iterate(&self, inode: &Inode, off: u64, f: &mut dyn FnMut(u64, u64, &str, FileType) -> bool) -> KResult<u64> {
        let d = inode.private::<ProcRootInode>().ok_or(VfsError::Einval)?;
        // Order: static children (sorted, the subdir tree) → self → live pids.
        let mut idx = off as usize;
        let nstat = d.children.len();
        while idx < nstat {
            let (name, child) = d.children.iter().nth(idx).unwrap();
            let next = idx as u64 + 1;
            if !f(child.ino(), next, name.as_str(), child.file_type()) { return Ok(next); }
            idx += 1;
        }
        let vpids = sched::live::registry::live_vpids();
        let total = nstat + 1 + vpids.len(); // +1 for "self"
        while idx < total {
            let dyn_idx = idx - nstat; // 0 = self, 1.. = pids
            let next = idx as u64 + 1;
            let mut buf = [0u8; 11];
            let s: &str = if dyn_idx == 0 {
                "self"
            } else {
                let mut t = vpids[dyn_idx - 1];
                let mut n = 0;
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
                core::str::from_utf8(&buf[..n]).unwrap_or("0")
            };
            let ino = inode.lookup(s).map(|i| i.ino()).unwrap_or(0);
            if !f(ino, next, s, FileType::Directory) {
                return Ok(next);
            }
            idx += 1;
        }
        Ok(idx as u64)
    }
}

/// The `/proc` root directory inode (Linux `proc_create` set in `children`).
/// # C: O(1)
pub fn make_proc_root(children: alloc::collections::BTreeMap<alloc::string::String, InodeRef>) -> InodeRef {
    InodeBuilder::new(0x3000_0001, mk_mode(FileType::Directory, 0o555), Arc::new(ProcRootOps), Arc::new(ProcRootOps))
        .private(Arc::new(ProcRootInode { children }))
        .build()
}
pub use crate::cgroup_file::make_proc_cgroup;
/// Per-pid `/proc/<tid>` directory. Synthesises status/cmdline/stat/maps.
pub struct ProcPidDirInode {
    pub tid: u32,
    pub is_self: bool,
    pub allow_task_dir: bool,
}

fn proc_pid_dir_lookup(d: &ProcPidDirInode, name: &str) -> KResult<InodeRef> {
    // /proc/self/<file>: static-registered devfs entries (exe/cwd/
    // root symlinks, /fd dir) take priority; else resolve `self` to
    // the running task's tid and fall through.
    let tid = if d.is_self {
        // Static `/proc/self/<file>` entries live under PROC_REG key
        // `self/<name>` (procfs's own tree, D1d) — exe/cwd/root symlinks,
        // /fd dir, auxv, limits, etc. take priority; else resolve `self`
        // to the running task's tid and fall through to the match arms.
        if let Some(i) = crate::reg::proc_reg().lookup_path(&alloc::format!("self/{name}")) {
            return Ok(i);
        }
        sched::live::current()
            .map(|c| c.tid)
            .ok_or(VfsError::Enoent)?
    } else {
        d.tid
    };
    match name {
        "status" => Ok(make_pid_status(tid)),
        "cmdline" => Ok(make_pid_cmdline(tid)),
        "stat" => Ok(make_pid_stat(tid)),
        "maps" => Ok(make_pid_maps(tid)),
        "smaps" => Ok(crate::smaps::make_proc_pid_smaps(tid)),
        "comm" => Ok(make_pid_comm(tid)),
        "environ" => Ok(make_pid_environ(tid)),
        "statm" => Ok(make_pid_statm(tid)),
        "wchan" => Ok(StaticFileInode::new(b"0")),
        "oom_score" => Ok(StaticFileInode::new(b"0\n")),
        "oom_score_adj" => Ok(crate::sysctl::SysctlInode::new(b"0\n")),
        "loginuid" => Ok(StaticFileInode::new(b"0\n")),
        "sessionid" => Ok(StaticFileInode::new(b"0\n")),
        "io" => {
            Ok(StaticFileInode::new(b"rchar: 0\nwchar: 0\nsyscr: 0\nsyscw: 0\n"))
        }
        "limits" => Ok(make_pid_limits(tid)),
        "personality" => Ok(StaticFileInode::new(b"00000000\n")),
        "sched" => Ok(make_pid_sched(tid)),
        "schedstat" => Ok(StaticFileInode::new(b"0 0 0\n")),
        "autogroup" => Ok(StaticFileInode::new(b"/autogroup-1 nice 0\n")),
        "task" if d.allow_task_dir => {
            let task = sched::live::registry::lookup(tid).ok_or(VfsError::Enoent)?;
            let tgid = task.tgid.load(Ordering::Acquire);
            Ok(make_proc_pid_task_dir(tgid))
        }
        // F117 / 26§R01: ns subdir. Lookup yields a NsDirInode
        // whose lookup(<type>) returns an NsInode with the task's
        // current id snapshot for that NS kind.
        "ns" => Ok(make_proc_pid_ns_dir(tid)),
        "uid_map" | "gid_map" => {
            Ok(crate::sysctl::SysctlInode::new(b"         0          0 4294967295\n"))
        }
        "setgroups" => Ok(crate::sysctl::SysctlInode::new(b"allow\n")),
        "syscall" => Ok(StaticFileInode::new(b"running\n")),
        "mounts" => Ok(crate::mounts::make_proc_mounts()),
        "mountinfo" => Ok(crate::mounts::make_proc_mountinfo()),
        "cgroup" => Ok(make_proc_cgroup(Some(tid))),
        "auxv" => Ok(StaticFileInode::new(&[0u8; 16])),
        "timerslack_ns" => Ok(StaticFileInode::new(b"50000\n")),
        "coredump_filter" => Ok(StaticFileInode::new(b"00000033\n")),
        "smaps_rollup" => Ok(crate::smaps::make_proc_pid_smaps(tid)),
        "numa_maps" => Ok(make_pid_maps(tid)),
        "projid_map" => Ok(crate::sysctl::SysctlInode::new(b"         0          0 4294967295\n")),
        "stack" | "mountstats" | "make-it-fail" | "fail-nth" | "pagemap"
        | "kpagecount" | "kpageflags" | "attr" => Ok(StaticFileInode::new(b"")),
        "wakeups_count" => Ok(StaticFileInode::new(b"0\n")),
        // exe/cwd/root: magic symlinks (followed by stat/O_PATH) per make_proc_pid_link.
        "exe" | "cwd" | "root" => Ok(crate::proc_links::make_proc_pid_link(tid, match name {
            "exe" => "exe",
            "cwd" => "cwd",
            _ => "root",
        })),
        "fd" => Ok(make_proc_self_fd()),
        "fdinfo" => Ok(crate::fdinfo::make_fdinfo_dir(if d.is_self { None } else { Some(tid) })),
        _ => Err(VfsError::Enoent),
    }
}

/// Single source of truth for the `/proc/<pid>` directory contents (Linux
/// `tgid_base_stuff[]`): drives readdir's listing AND each entry's `d_type`,
/// replacing the old separate `ENTRIES` array + ad-hoc type `match` that could
/// drift from `proc_pid_dir_lookup`'s arms (D25). Every name here is resolved
/// by `proc_pid_dir_lookup`; `task` is emitted only for a thread-group-leader
/// dir (`allow_task_dir`). # C: O(1)
const PID_ENTRIES: &[(&str, FileType)] = &[
    ("status",          FileType::Regular),
    ("cmdline",         FileType::Regular),
    ("stat",            FileType::Regular),
    ("maps",            FileType::Regular),
    ("smaps",           FileType::Regular),
    ("smaps_rollup",    FileType::Regular),
    ("numa_maps",       FileType::Regular),
    ("comm",            FileType::Regular),
    ("environ",         FileType::Regular),
    ("statm",           FileType::Regular),
    ("wchan",           FileType::Regular),
    ("oom_score",       FileType::Regular),
    ("oom_score_adj",   FileType::Regular),
    ("loginuid",        FileType::Regular),
    ("sessionid",       FileType::Regular),
    ("io",              FileType::Regular),
    ("limits",          FileType::Regular),
    ("personality",     FileType::Regular),
    ("sched",           FileType::Regular),
    ("schedstat",       FileType::Regular),
    ("autogroup",       FileType::Regular),
    ("uid_map",         FileType::Regular),
    ("gid_map",         FileType::Regular),
    ("setgroups",       FileType::Regular),
    ("syscall",         FileType::Regular),
    ("stack",           FileType::Regular),
    ("mounts",          FileType::Regular),
    ("mountinfo",       FileType::Regular),
    ("mountstats",      FileType::Regular),
    ("cgroup",          FileType::Regular),
    ("auxv",            FileType::Regular),
    ("timerslack_ns",   FileType::Regular),
    ("coredump_filter", FileType::Regular),
    ("exe",             FileType::Symlink),
    ("cwd",             FileType::Symlink),
    ("root",            FileType::Symlink),
    ("fd",              FileType::Directory),
    ("fdinfo",          FileType::Directory),
];

struct ProcPidDirOps;
impl InodeOps for ProcPidDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<ProcPidDirInode>().ok_or(VfsError::Einval)?;
        proc_pid_dir_lookup(d, name)
    }
}
impl FileOps for ProcPidDirOps {
    fn iterate(&self, inode: &Inode, off: u64, f: &mut dyn FnMut(u64, u64, &str, FileType) -> bool) -> KResult<u64> {
        let d = inode.private::<ProcPidDirInode>().ok_or(VfsError::Einval)?;
        let mut idx = off as usize;
        let total = PID_ENTRIES.len() + usize::from(d.allow_task_dir);
        while idx < total {
            let next = idx as u64 + 1;
            let (name, ft) = if idx < PID_ENTRIES.len() {
                PID_ENTRIES[idx]
            } else {
                ("task", FileType::Directory)
            };
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !f(ino, next, name, ft) {
                return Ok(next);
            }
            idx += 1;
        }
        Ok(idx as u64)
    }
}

/// Per-pid `/proc/<tid>` directory inode. # C: O(1)
pub fn make_proc_pid_dir(tid: u32, is_self: bool, allow_task_dir: bool) -> InodeRef {
    InodeBuilder::new(pid_ino(0x01, tid), mk_mode(FileType::Directory, 0o555), Arc::new(ProcPidDirOps), Arc::new(ProcPidDirOps))
        .private(Arc::new(ProcPidDirInode { tid, is_self, allow_task_dir }))
        .build()
}

pub struct ProcPidTaskDirInode {
    pub tgid: u32,
}

fn proc_pid_task_dir_lookup(d: &ProcPidTaskDirInode, name: &str) -> KResult<InodeRef> {
    let want: u32 = name.parse().map_err(|_| VfsError::Enoent)?;
    let tid = sched::live::registry::thread_entries(d.tgid)
        .into_iter()
        .find_map(|(vtid, tid)| if vtid == want { Some(tid) } else { None })
        .ok_or(VfsError::Enoent)?;
    Ok(make_proc_pid_dir(tid, false, false))
}

struct ProcPidTaskDirOps;
impl InodeOps for ProcPidTaskDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<ProcPidTaskDirInode>().ok_or(VfsError::Einval)?;
        proc_pid_task_dir_lookup(d, name)
    }
}
impl FileOps for ProcPidTaskDirOps {
    fn iterate(&self, inode: &Inode, off: u64, f: &mut dyn FnMut(u64, u64, &str, FileType) -> bool) -> KResult<u64> {
        let d = inode.private::<ProcPidTaskDirInode>().ok_or(VfsError::Einval)?;
        let tids = sched::live::registry::thread_entries(d.tgid);
        let mut idx = off as usize;
        while idx < tids.len() {
            let next = idx as u64 + 1;
            let mut buf = [0u8; 11];
            let mut t = tids[idx].0;
            let mut n = 0;
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
            let ino = inode.lookup(s).map(|i| i.ino()).unwrap_or(0);
            if !f(ino, next, s, FileType::Directory) {
                return Ok(next);
            }
            idx += 1;
        }
        Ok(idx as u64)
    }
}

/// Per-pid `/proc/<tgid>/task` thread directory inode. # C: O(1)
pub fn make_proc_pid_task_dir(tgid: u32) -> InodeRef {
    InodeBuilder::new(pid_ino(0x07, tgid), mk_mode(FileType::Directory, 0o555), Arc::new(ProcPidTaskDirOps), Arc::new(ProcPidTaskDirOps))
        .private(Arc::new(ProcPidTaskDirInode { tgid }))
        .build()
}

fn pid_status_body(tid: u32) -> alloc::vec::Vec<u8> {
    crate::pid_status::body(tid)
}

fn pid_cmdline_body(tid: u32) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(64);
    let task = match sched::live::registry::lookup(tid) {
        Some(t) => t,
        None => return out,
    };
    // SAFETY: snapshot of cmdline slot; written only by the task itself per `13§5`.
    let snap = unsafe { (*task.cmdline.get()).clone() };
    if let Some(s) = snap {
        push(&mut out, s.as_bytes());
    } else {
        push(&mut out, task.name.as_bytes());
        out.push(0);
    }
    out
}

fn pid_stat_body(tid: u32) -> alloc::vec::Vec<u8> {
    crate::pid_stat::body(tid)
}

fn pid_maps_body(tid: u32) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(1024);
    let task = match sched::live::registry::lookup(tid) {
        Some(t) => t,
        None => return out,
    };
    // SAFETY: mm slot read-only borrow; single-mutator per `13§5`.
    let mm = match unsafe { (*task.mm.get()).as_ref() } {
        Some(m) => m.clone(),
        None => return out,
    };
    for vma in mm.snapshot_vmas() {
        push_hex(&mut out, vma.start.as_u64());
        out.push(b'-');
        push_hex(&mut out, vma.end.as_u64());
        out.push(b' ');
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
        out.push(b'p');
        push(&mut out, b" 00000000 00:00 0 \n");
    }
    out
}

/// Per-pid `/proc/<tid>/<file>` constructor: a read-only regular inode whose
/// body is `$body(tid)`. Mirrors the old `pid_inode_impl!` macro but stamps a
/// KEYSTONE struct-`Inode` via `dyn_file::make_pid_gen_file`.
macro_rules! pid_inode_ctor {
    ($ctor:ident, $body:ident, $tag:expr) => {
        /// Per-pid `/proc/<tid>` file inode. # C: O(1)
        pub fn $ctor(tid: u32) -> InodeRef {
            crate::dyn_file::make_pid_gen_file(pid_ino($tag, tid), tid, $body)
        }
    };
}

pid_inode_ctor!(make_pid_status, pid_status_body, 0x20);
pid_inode_ctor!(make_pid_cmdline, pid_cmdline_body, 0x21);
pid_inode_ctor!(make_pid_stat, pid_stat_body, 0x22);
pid_inode_ctor!(make_pid_maps, pid_maps_body, 0x23);
pid_inode_ctor!(make_pid_comm, pid_comm_body, 0x24);
pid_inode_ctor!(make_pid_environ, pid_environ_body, 0x25);
pid_inode_ctor!(make_pid_statm, pid_statm_body, 0x26);
pid_inode_ctor!(make_pid_limits, pid_limits_body, 0x28);

/// Render /proc/<pid>/limits from the live per-task rlimit slot.
fn pid_limits_body(tid: u32) -> alloc::vec::Vec<u8> {
    use sched::rlimit::{format_rlim, rlim};
    let mut out = alloc::vec::Vec::with_capacity(2048);
    let task = match sched::live::registry::lookup(tid) {
        Some(t) => t,
        None => return out,
    };
    push(
        &mut out,
        b"Limit                     Soft Limit           Hard Limit           Units\n",
    );
    let names: &[(usize, &[u8], &[u8])] = &[
        (rlim::CPU, b"Max cpu time             ", b"seconds"),
        (rlim::FSIZE, b"Max file size            ", b"bytes"),
        (rlim::DATA, b"Max data size            ", b"bytes"),
        (rlim::STACK, b"Max stack size           ", b"bytes"),
        (rlim::CORE, b"Max core file size       ", b"bytes"),
        (rlim::RSS, b"Max resident set         ", b"bytes"),
        (rlim::NPROC, b"Max processes            ", b"processes"),
        (rlim::NOFILE, b"Max open files           ", b"files"),
        (rlim::MEMLOCK, b"Max locked memory        ", b"bytes"),
        (rlim::AS, b"Max address space        ", b"bytes"),
        (rlim::LOCKS, b"Max file locks           ", b"locks"),
        (rlim::SIGPENDING, b"Max pending signals      ", b"signals"),
        (rlim::MSGQUEUE, b"Max msgqueue size        ", b"bytes"),
        (rlim::NICE, b"Max nice priority        ", b""),
        (rlim::RTPRIO, b"Max realtime priority    ", b""),
        (rlim::RTTIME, b"Max realtime timeout     ", b"us"),
    ];
    // SAFETY: rlimits slot single-mutator per `13§5`; reading a snapshot.
    let limits = unsafe { *task.rlimits.get() };
    let mut buf = [0u8; 32];
    for (i, label, units) in names {
        push(&mut out, label);
        let n = format_rlim(&mut buf, limits[*i].0).unwrap_or(0);
        push(&mut out, &buf[..n]);
        for _ in n..21 {
            out.push(b' ');
        }
        let n = format_rlim(&mut buf, limits[*i].1).unwrap_or(0);
        push(&mut out, &buf[..n]);
        for _ in n..21 {
            out.push(b' ');
        }
        push(&mut out, units);
        out.push(b'\n');
    }
    out
}
use crate::pid_sched::pid_sched_body;
pid_inode_ctor!(make_pid_sched, pid_sched_body, 0x27);

fn pid_statm_body(tid: u32) -> alloc::vec::Vec<u8> {
    // statm fields (in pages of 4 KiB): size resident shared text lib data dt
    // v1: report total VMA range as size + resident; others 0.
    let mut out = alloc::vec::Vec::with_capacity(48);
    let task = match sched::live::registry::lookup(tid) {
        Some(t) => t,
        None => return out,
    };
    // SAFETY: mm slot single-mutator per `13§5`.
    let pages = match unsafe { (*task.mm.get()).as_ref() } {
        Some(mm) => mm
            .snapshot_vmas()
            .iter()
            .map(|v| (v.end.as_u64() - v.start.as_u64()) / 4096)
            .sum::<u64>(),
        None => 0,
    };
    push_u64(&mut out, pages);
    out.push(b' ');
    push_u64(&mut out, pages);
    out.push(b' ');
    push(&mut out, b"0 0 0 0 0\n");
    out
}

fn pid_comm_body(tid: u32) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(32);
    let task = match sched::live::registry::lookup(tid) {
        Some(t) => t,
        None => return out,
    };
    push(&mut out, task.name.as_bytes());
    out.push(b'\n');
    out
}

fn pid_environ_body(tid: u32) -> alloc::vec::Vec<u8> {
    let task = match sched::live::registry::lookup(tid) {
        Some(t) => t,
        None => return alloc::vec::Vec::new(),
    };
    // SAFETY: environ slot single-mutator per `13§5`.
    match unsafe { (*task.environ.get()).clone() } {
        Some(s) => s.into_bytes(),
        None => alloc::vec::Vec::new(),
    }
}

/// Resolve dynamic `/proc/<tid>[/<file>]` paths. Returns `None` for
/// non-procfs paths; callers fall back to the static devfs registry.
/// Path-shape parsing lives in `crates/crate::paths` (hosted-tested).
/// Linux-visible PID (vtgid) → kernel TID; falls back to raw-tid.
fn pid_to_kernel_tid(p: u32) -> Option<u32> {
    use sched::live::registry::{lookup, lookup_by_vpid};
    lookup_by_vpid(p).or_else(|| lookup(p)).map(|t| t.tid)
}

fn lookup_child_path(mut node: InodeRef, leaf: &str) -> Option<InodeRef> {
    if leaf.is_empty() {
        return Some(node);
    }
    for seg in leaf.split('/') {
        if seg.is_empty() {
            return None;
        }
        node = node.lookup(seg).ok()?;
    }
    Some(node)
}

/// Register the v1 procfs entries (delegated to procfs_static).
/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(N_files)
pub fn init() {
    crate::static_files::register_static_files();
}

/// Boot-time smoke for the registered files.
/// # SAFETY: caller is the boot path; pre-init.
/// # C: O(N)
pub fn smoke_test() {
    use hal::kassert;
    // Per-component resolve: `/proc/<leaf>` via the procfs root inode tree
    // (`ProcRootInode::lookup` → `i_op->lookup`), everything else via the
    // devfs key/value tree. No whole-path `FileSystem::lookup`.
    fn smoke_resolve(path: &str) -> Option<InodeRef> {
        // /proc/* walks procfs's own root inode tree; /sys/* sysfs's own
        // SYS_ROOT (D1c) — devfs no longer backs either. /etc is devfs's own
        // overlay and is smoked in `devfs::boot` now (D1d).
        if let Some(rest) = path.strip_prefix("/proc/") {
            return lookup_child_path(crate::static_files::proc_root() as InodeRef, rest);
        }
        if let Some(rest) = path.strip_prefix("/sys/") {
            return sysfs::sys_root().lookup_path(rest);
        }
        None
    }
    fn is_hex(b: u8) -> bool {
        b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
    }
    fn is_uuid_line(buf: &[u8]) -> bool {
        if buf.len() < 37 || buf[36] != b'\n' { return false; }
        for i in 0..36 {
            match i {
                8 | 13 | 18 | 23 => {
                    if buf[i] != b'-' { return false; }
                }
                _ => {
                    if !is_hex(buf[i]) { return false; }
                }
            }
        }
        buf[..36].iter().any(|&b| b != b'0' && b != b'-')
    }
    let entries: &[(&str, &[u8])] = &[
        ("/proc/version", b"Linux"),
        ("/proc/cpuinfo", b"processor"),
        ("/proc/meminfo", b"MemTotal:"),
        // /proc/uptime is dynamic now (P3-111) — skipped from smoke (its body is
        // a function of monotonic_ns, not a static prefix).
        // /proc/sys + /proc/net now resolve from procfs's own PROC_REG tree.
        ("/proc/sys/kernel/pid_max", b"32768"),
        ("/proc/sys/kernel/domainname", b"(none)"),
        ("/proc/net/dev", b"Inter-|"),
    ];
    for (path, prefix) in entries {
        // Resolve through the procfs filesystem (the /proc dir tree owns its
        // static children now; /sys + /etc still fall to devfs inside it).
        let inode = smoke_resolve(path).expect("procfs lookup");
        let mut buf = [0u8; 32];
        let n = inode.read(0, &mut buf).expect("procfs read");
        kassert!(n >= prefix.len(), "procfs read short");
        kassert!(&buf[..prefix.len()] == *prefix, "procfs body mismatch");
    }
    for path in ["/sys/kernel/random/uuid", "/sys/kernel/random/boot_id"] {
        let inode = smoke_resolve(path).expect("procfs lookup");
        let mut buf = [0u8; 40];
        let n = inode.read(0, &mut buf).expect("procfs read");
        kassert!(n == 37, "procfs uuid length mismatch");
        kassert!(is_uuid_line(&buf[..n]), "procfs uuid shape mismatch");
    }
    debug_boot! { klog::write_raw(b"[INFO]  procfs-smoke: ok\n"); }
}

/// `/proc/<pid>/ns` directory inode. F117. Lookup yields an NsInode
/// snapshotting the target task's current id for that NS kind;
/// readdir enumerates the seven subentries.
pub struct ProcPidNsDirInode {
    pub tid: u32,
}

struct ProcPidNsDirOps;
impl InodeOps for ProcPidNsDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<ProcPidNsDirInode>().ok_or(VfsError::Einval)?;
        let kind = match nscg::proc_ns::NsKind::from_leaf(name) {
            Some(k) => k,
            None => return Err(VfsError::Enoent),
        };
        let task = match sched::live::registry::lookup(d.tid) {
            Some(t) => t,
            None => return Err(VfsError::Enoent),
        };
        Ok(nscg::proc_ns::ns_inode_for(&task, kind))
    }
}
impl FileOps for ProcPidNsDirOps {
    fn iterate(&self, inode: &Inode, off: u64, f: &mut dyn FnMut(u64, u64, &str, FileType) -> bool) -> KResult<u64> {
        const NAMES: &[&str] = &[
            "mnt",
            "cgroup",
            "uts",
            "ipc",
            "user",
            "pid",
            "net",
            "pid_for_children",
        ];
        let mut idx = off as usize;
        while idx < NAMES.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup(NAMES[idx]).map(|i| i.ino()).unwrap_or(0);
            if !f(ino, next, NAMES[idx], FileType::Symlink) {
                return Ok(next);
            }
            idx += 1;
        }
        Ok(idx as u64)
    }
}

/// `/proc/<pid>/ns` directory inode (F117). # C: O(1)
pub fn make_proc_pid_ns_dir(tid: u32) -> InodeRef {
    InodeBuilder::new(pid_ino(0x08, tid), mk_mode(FileType::Directory, 0o555), Arc::new(ProcPidNsDirOps), Arc::new(ProcPidNsDirOps))
        .private(Arc::new(ProcPidNsDirInode { tid }))
        .build()
}
