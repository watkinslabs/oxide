//! Kernel-side procfs integration. Body builders live in
//! crates/kernel/procfs (target-clean); the kernel-side mounting
//! and per-pid wiring stays here.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

pub static NEXT_INO: AtomicU64 = AtomicU64::new(0x3000_0000);

/// Static-body procfs file. `read(off, buf)` returns the window
/// `body[off..off+buf.len()]` clamped to body length.
use crate::StaticFileInode;

// `/proc/self/*` + system pseudo-files split out (1000-line cap, docs/08§7).
mod self_files;
pub use self_files::*;

pub struct ProcRootInode;

impl Inode for ProcRootInode {
    fn ino(&self) -> Ino {
        0x3000_0001
    }
    fn file_type(&self) -> FileType {
        FileType::Directory
    }
    fn size(&self) -> u64 {
        0
    }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        if name == "self" {
            return Ok(Arc::new(ProcPidDirInode {
                tid: 0,
                is_self: true,
                allow_task_dir: true,
            }) as InodeRef);
        }
        // `name` is a Linux PID (vtgid); translate via pid_to_kernel_tid.
        let vpid: u32 = name.parse().map_err(|_| VfsError::Enoent)?;
        let tid = pid_to_kernel_tid(vpid).ok_or(VfsError::Enoent)?;
        Ok(Arc::new(ProcPidDirInode {
            tid,
            is_self: false,
            allow_task_dir: true,
        }) as InodeRef)
    }
    fn readdir(&self, off: u64, f: &mut dyn FnMut(u64, &str, FileType) -> bool) -> KResult<u64> {
        let mut idx = off as usize;
        let vpids = sched::live::registry::live_vpids();
        let total = vpids.len() + 1; // +1 for "self"
        while idx < total {
            let next = idx as u64 + 1;
            let mut buf = [0u8; 11];
            let s: &str = if idx == 0 {
                "self"
            } else {
                let mut t = vpids[idx - 1];
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
            if !f(next, s, FileType::Directory) {
                return Ok(next);
            }
            idx += 1;
        }
        Ok(idx as u64)
    }
}
pub use crate::cgroup_file::ProcCgroupInode;
/// Per-pid `/proc/<tid>` directory. Synthesises status/cmdline/stat/maps.
pub struct ProcPidDirInode {
    pub tid: u32,
    pub is_self: bool,
    pub allow_task_dir: bool,
}

impl Inode for ProcPidDirInode {
    fn ino(&self) -> Ino {
        0x3000_0100 | self.tid as Ino
    }
    fn file_type(&self) -> FileType {
        FileType::Directory
    }
    fn size(&self) -> u64 {
        0
    }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        // /proc/self/<file>: static-registered devfs entries (exe/cwd/
        // root symlinks, /fd dir) take priority; else resolve `self` to
        // the running task's tid and fall through.
        let tid = if self.is_self {
            let mut p = alloc::string::String::with_capacity(11 + name.len());
            p.push_str("/proc/self/");
            p.push_str(name);
            if let Some(i) = devfs::lookup(&p) {
                return Ok(i);
            }
            sched::live::current()
                .map(|c| c.tid)
                .ok_or(VfsError::Enoent)?
        } else {
            self.tid
        };
        match name {
            "status" => Ok(Arc::new(ProcPidStatusInode { tid }) as InodeRef),
            "cmdline" => Ok(Arc::new(ProcPidCmdlineInode { tid }) as InodeRef),
            "stat" => Ok(Arc::new(ProcPidStatInode { tid }) as InodeRef),
            "maps" => Ok(Arc::new(ProcPidMapsInode { tid }) as InodeRef),
            "smaps" => Ok(Arc::new(crate::smaps::ProcPidSmapsInode { tid }) as InodeRef),
            "comm" => Ok(Arc::new(ProcPidCommInode { tid }) as InodeRef),
            "environ" => Ok(Arc::new(ProcPidEnvironInode { tid }) as InodeRef),
            "statm" => Ok(Arc::new(ProcPidStatmInode { tid }) as InodeRef),
            "wchan" => Ok(StaticFileInode::new(b"0") as InodeRef),
            "oom_score" => Ok(StaticFileInode::new(b"0\n") as InodeRef),
            "oom_score_adj" => Ok(StaticFileInode::new(b"0\n") as InodeRef),
            "loginuid" => Ok(StaticFileInode::new(b"0\n") as InodeRef),
            "sessionid" => Ok(StaticFileInode::new(b"0\n") as InodeRef),
            "io" => {
                Ok(StaticFileInode::new(b"rchar: 0\nwchar: 0\nsyscr: 0\nsyscw: 0\n") as InodeRef)
            }
            "limits" => Ok(Arc::new(ProcPidLimitsInode { tid }) as InodeRef),
            "personality" => Ok(StaticFileInode::new(b"00000000\n") as InodeRef),
            "sched" => Ok(Arc::new(ProcPidSchedInode { tid }) as InodeRef),
            "schedstat" => Ok(StaticFileInode::new(b"0 0 0\n") as InodeRef),
            "autogroup" => Ok(StaticFileInode::new(b"/autogroup-1 nice 0\n") as InodeRef),
            "task" if self.allow_task_dir => {
                let task = sched::live::registry::lookup(tid).ok_or(VfsError::Enoent)?;
                let tgid = task.tgid.load(Ordering::Acquire);
                Ok(Arc::new(ProcPidTaskDirInode { tgid }) as InodeRef)
            }
            // F117 / 26§R01: ns subdir. Lookup yields a NsDirInode
            // whose lookup(<type>) returns an NsInode with the task's
            // current id snapshot for that NS kind.
            "ns" => Ok(Arc::new(ProcPidNsDirInode { tid }) as InodeRef),
            "uid_map" | "gid_map" => {
                Ok(StaticFileInode::new(b"         0          0 4294967295\n") as InodeRef)
            }
            "setgroups" => Ok(StaticFileInode::new(b"allow\n") as InodeRef),
            "syscall" => Ok(StaticFileInode::new(b"running\n") as InodeRef),
            "mounts" => Ok(Arc::new(crate::mounts::ProcMountsInode) as InodeRef),
            "mountinfo" => Ok(Arc::new(crate::mounts::ProcMountinfoInode) as InodeRef),
            "cgroup" => Ok(Arc::new(ProcCgroupInode { tid: Some(tid) }) as InodeRef),
            "auxv" => Ok(StaticFileInode::new(&[0u8; 16]) as InodeRef),
            "timerslack_ns" => Ok(StaticFileInode::new(b"50000\n") as InodeRef),
            "coredump_filter" => Ok(StaticFileInode::new(b"00000033\n") as InodeRef),
            "smaps_rollup" => Ok(Arc::new(crate::smaps::ProcPidSmapsInode { tid }) as InodeRef),
            "numa_maps" => Ok(Arc::new(ProcPidMapsInode { tid }) as InodeRef),
            "stack" | "mountstats" | "make-it-fail" | "fail-nth" | "projid_map" | "pagemap"
            | "kpagecount" | "kpageflags" | "attr" => Ok(StaticFileInode::new(b"") as InodeRef),
            "wakeups_count" => Ok(StaticFileInode::new(b"0\n") as InodeRef),
            // exe/cwd/root: magic symlinks (followed by stat/O_PATH) per ProcPidLinkInode.
            "exe" | "cwd" | "root" => Ok(Arc::new(crate::proc_links::ProcPidLinkInode {
                tid,
                leaf: match name {
                    "exe" => "exe",
                    "cwd" => "cwd",
                    _ => "root",
                },
            }) as InodeRef),
            "fd" => Ok(Arc::new(ProcSelfFdInode) as InodeRef),
            "fdinfo" => Ok(Arc::new(crate::fdinfo::ProcFdInfoDirInode {
                tid_opt: if self.is_self { None } else { Some(tid) },
            }) as InodeRef),
            _ => Err(VfsError::Enoent),
        }
    }
    fn readdir(&self, off: u64, f: &mut dyn FnMut(u64, &str, FileType) -> bool) -> KResult<u64> {
        const ENTRIES: &[&str] = &[
            "status",
            "cmdline",
            "stat",
            "maps",
            "smaps",
            "smaps_rollup",
            "numa_maps",
            "comm",
            "environ",
            "statm",
            "wchan",
            "oom_score",
            "oom_score_adj",
            "loginuid",
            "sessionid",
            "io",
            "limits",
            "personality",
            "sched",
            "schedstat",
            "autogroup",
            "uid_map",
            "gid_map",
            "setgroups",
            "syscall",
            "stack",
            "mounts",
            "mountinfo",
            "mountstats",
            "cgroup",
            "auxv",
            "timerslack_ns",
            "coredump_filter",
            "exe",
            "cwd",
            "root",
            "fd",
            "fdinfo",
        ];
        let mut idx = off as usize;
        let total = ENTRIES.len() + usize::from(self.allow_task_dir);
        while idx < total {
            let next = idx as u64 + 1;
            let name = if idx < ENTRIES.len() {
                ENTRIES[idx]
            } else {
                "task"
            };
            let ft = match name {
                "exe" | "cwd" | "root" => FileType::Symlink,
                "fd" | "fdinfo" | "task" => FileType::Directory,
                _ => FileType::Regular,
            };
            if !f(next, name, ft) {
                return Ok(next);
            }
            idx += 1;
        }
        Ok(idx as u64)
    }
}

pub struct ProcPidTaskDirInode {
    pub tgid: u32,
}

impl Inode for ProcPidTaskDirInode {
    fn ino(&self) -> Ino {
        0x3000_7000 | self.tgid as Ino
    }
    fn file_type(&self) -> FileType {
        FileType::Directory
    }
    fn size(&self) -> u64 {
        0
    }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        let want: u32 = name.parse().map_err(|_| VfsError::Enoent)?;
        let tid = sched::live::registry::thread_entries(self.tgid)
            .into_iter()
            .find_map(|(vtid, tid)| if vtid == want { Some(tid) } else { None })
            .ok_or(VfsError::Enoent)?;
        Ok(Arc::new(ProcPidDirInode {
            tid,
            is_self: false,
            allow_task_dir: false,
        }) as InodeRef)
    }
    fn readdir(&self, off: u64, f: &mut dyn FnMut(u64, &str, FileType) -> bool) -> KResult<u64> {
        let tids = sched::live::registry::thread_entries(self.tgid);
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
            if !f(next, s, FileType::Directory) {
                return Ok(next);
            }
            idx += 1;
        }
        Ok(idx as u64)
    }
}

/// Per-pid status. Body mirrors `ProcSelfStatusInode` but resolves
/// the target via `sched::registry::lookup(tid)`.
pub struct ProcPidStatusInode {
    pub tid: u32,
}
pub struct ProcPidCmdlineInode {
    pub tid: u32,
}
pub struct ProcPidStatInode {
    pub tid: u32,
}
pub struct ProcPidMapsInode {
    pub tid: u32,
}
pub struct ProcPidCommInode {
    pub tid: u32,
}
pub struct ProcPidEnvironInode {
    pub tid: u32,
}
pub struct ProcPidStatmInode {
    pub tid: u32,
}
pub struct ProcPidLimitsInode {
    pub tid: u32,
}
pub struct ProcPidSchedInode {
    pub tid: u32,
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

macro_rules! pid_inode_impl {
    ($t:ident, $body:ident, $ino:expr) => {
        impl Inode for $t {
            fn ino(&self) -> Ino {
                $ino | self.tid as Ino
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
                let body = $body(self.tid);
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
    };
}

pid_inode_impl!(ProcPidStatusInode, pid_status_body, 0x3000_2000);
pid_inode_impl!(ProcPidCmdlineInode, pid_cmdline_body, 0x3000_2100);
pid_inode_impl!(ProcPidStatInode, pid_stat_body, 0x3000_2200);
pid_inode_impl!(ProcPidMapsInode, pid_maps_body, 0x3000_2300);
pid_inode_impl!(ProcPidCommInode, pid_comm_body, 0x3000_2400);
pid_inode_impl!(ProcPidEnvironInode, pid_environ_body, 0x3000_2500);
pid_inode_impl!(ProcPidStatmInode, pid_statm_body, 0x3000_2600);
pid_inode_impl!(ProcPidLimitsInode, pid_limits_body, 0x3000_2800);

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
pid_inode_impl!(ProcPidSchedInode, pid_sched_body, 0x3000_2700);

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

/// # C: O(N_tasks)
pub fn lookup_dynamic(path: &str) -> Option<InodeRef> {
    use crate::paths::{parse_proc_path, ProcPath};
    if let Some(i) = crate::proc_links::lookup_fd_path(path) {
        return Some(i);
    }
    if let Some(i) = crate::fdinfo::lookup_fdinfo_path(path) {
        return Some(i);
    }
    match parse_proc_path(path) {
        ProcPath::SelfDir => Some(Arc::new(ProcPidDirInode {
            tid: 0,
            is_self: true,
            allow_task_dir: true,
        }) as InodeRef),
        ProcPath::SelfChild(leaf) => {
            // Static devfs registrations take priority (already tried by
            // caller). Fall back to the same per-pid synthesis as
            // /proc/<pid>/<leaf> via the is_self dispatch.
            lookup_child_path(
                Arc::new(ProcPidDirInode {
                    tid: 0,
                    is_self: true,
                    allow_task_dir: true,
                }) as InodeRef,
                leaf,
            )
        }
        ProcPath::PidDir(name_pid) => {
            let tid = pid_to_kernel_tid(name_pid)?;
            Some(Arc::new(ProcPidDirInode {
                tid,
                is_self: false,
                allow_task_dir: true,
            }) as InodeRef)
        }
        ProcPath::PidChild(name_pid, leaf) => {
            let tid = pid_to_kernel_tid(name_pid)?;
            lookup_child_path(
                Arc::new(ProcPidDirInode {
                    tid,
                    is_self: false,
                    allow_task_dir: true,
                }) as InodeRef,
                leaf,
            )
        }
        ProcPath::NotProc => match path {
            "/proc/net/dev" => Some(Arc::new(crate::net::ProcNetDevInode) as InodeRef),
            "/proc/net/tcp" => Some(Arc::new(crate::net::ProcNetTcpInode) as InodeRef),
            "/proc/net/udp" => Some(Arc::new(crate::net::ProcNetUdpInode) as InodeRef),
            "/proc/modules" => Some(Arc::new(crate::net::ProcModulesInode) as InodeRef),
            "/proc/net/route" => Some(Arc::new(crate::net::ProcNetRouteInode) as InodeRef),
            "/proc/net/arp" => Some(Arc::new(crate::net::ProcNetArpInode) as InodeRef),
            "/proc/net/unix" => Some(Arc::new(crate::net::ProcNetUnixInode) as InodeRef),
            "/proc/net/if_inet6" => Some(Arc::new(crate::net::ProcNetIfInet6Inode) as InodeRef),
            "/proc/net/snmp" => Some(Arc::new(crate::net::ProcNetSnmpInode) as InodeRef),
            _ => None,
        },
    }
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
    use vfs::Inode;
    let entries: &[(&str, &[u8])] = &[
        ("/proc/version", b"Linux"),
        ("/proc/cpuinfo", b"processor"),
        ("/proc/meminfo", b"MemTotal:"),
        // /proc/uptime is dynamic now (P3-111) — skipped from smoke (its body is
        // a function of monotonic_ns, not a static prefix).
        ("/sys/kernel/random/uuid", b"00000000"),
        ("/sys/kernel/random/boot_id", b"00000000"),
        ("/etc/os-release", b"NAME=oxide"),
    ];
    for (path, prefix) in entries {
        let inode = devfs::lookup(path).expect("procfs lookup");
        let mut buf = [0u8; 32];
        let n = inode.read(0, &mut buf).expect("procfs read");
        kassert!(n >= prefix.len(), "procfs read short");
        kassert!(&buf[..prefix.len()] == *prefix, "procfs body mismatch");
    }
    debug_boot! { klog::write_raw(b"[INFO]  procfs-smoke: ok\n"); }
}

/// `/proc/<pid>/ns` directory inode. F117. Lookup yields an NsInode
/// snapshotting the target task's current id for that NS kind;
/// readdir enumerates the seven subentries.
pub struct ProcPidNsDirInode {
    pub tid: u32,
}

impl Inode for ProcPidNsDirInode {
    fn ino(&self) -> Ino {
        0x3000_8000 | (self.tid as Ino)
    }
    fn file_type(&self) -> FileType {
        FileType::Directory
    }
    fn size(&self) -> u64 {
        0
    }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        let kind = match nscg::proc_ns::NsKind::from_leaf(name) {
            Some(k) => k,
            None => return Err(VfsError::Enoent),
        };
        let task = match sched::live::registry::lookup(self.tid) {
            Some(t) => t,
            None => return Err(VfsError::Enoent),
        };
        Ok(nscg::proc_ns::ns_inode_for(&task, kind))
    }
    fn readdir(&self, off: u64, f: &mut dyn FnMut(u64, &str, FileType) -> bool) -> KResult<u64> {
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
            if !f(next, NAMES[idx], FileType::Symlink) {
                return Ok(next);
            }
            idx += 1;
        }
        Ok(idx as u64)
    }
}
