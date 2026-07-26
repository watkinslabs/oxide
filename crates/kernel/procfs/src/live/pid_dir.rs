use alloc::format;
use alloc::sync::Arc;

use core::sync::atomic::Ordering;
use vfs::{DirContext, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError, mk_mode};

use super::ns_dir::make_proc_pid_ns_dir;
use super::pid_attr::make_proc_pid_attr_dir;
use super::{make_pid_oom_score, make_pid_oom_score_adj};
use super::pid_files::{
    make_pid_cmdline, make_pid_comm, make_pid_environ, make_pid_io, make_pid_limits, make_pid_maps,
    make_pid_sched, make_pid_stat, make_pid_statm, make_pid_status,
};
use super::pid_ino;
use super::self_files::make_proc_fd_dir;
use crate::StaticFileInode;

pub struct ProcPidDirInode {
    pub tid: u32,
    pub is_self: bool,
    pub allow_task_dir: bool,
}

type PidCtor = fn(u32, bool) -> InodeRef;

fn pc_status(t: u32, _s: bool) -> InodeRef { make_pid_status(t) }
fn pc_cmdline(t: u32, _s: bool) -> InodeRef { make_pid_cmdline(t) }
fn pc_stat(t: u32, _s: bool) -> InodeRef { make_pid_stat(t) }
fn pc_maps(t: u32, _s: bool) -> InodeRef { make_pid_maps(t) }
fn pc_smaps(t: u32, _s: bool) -> InodeRef { crate::smaps::make_proc_pid_smaps(t) }
fn pc_comm(t: u32, _s: bool) -> InodeRef { make_pid_comm(t) }
fn pc_environ(t: u32, _s: bool) -> InodeRef { make_pid_environ(t) }
fn pc_statm(t: u32, _s: bool) -> InodeRef { make_pid_statm(t) }
fn pc_wchan(_t: u32, _s: bool) -> InodeRef { StaticFileInode::new(b"0") }
fn pc_oom_score(t: u32, _s: bool) -> InodeRef { make_pid_oom_score(t) }
fn pc_oom_score_adj(t: u32, _s: bool) -> InodeRef { make_pid_oom_score_adj(t) }
fn pc_loginuid(_t: u32, _s: bool) -> InodeRef { crate::sysctl::SysctlInode::new(b"4294967295\n") }
fn pc_sessionid(_t: u32, _s: bool) -> InodeRef { StaticFileInode::new(b"0\n") }
fn pc_io(t: u32, _s: bool) -> InodeRef { make_pid_io(t) }
fn pc_limits(t: u32, _s: bool) -> InodeRef { make_pid_limits(t) }
fn pc_personality(_t: u32, _s: bool) -> InodeRef { StaticFileInode::new(b"00000000\n") }
fn pc_sched(t: u32, _s: bool) -> InodeRef { make_pid_sched(t) }
fn pc_schedstat(_t: u32, _s: bool) -> InodeRef { StaticFileInode::new(b"0 0 0\n") }
fn pc_autogroup(_t: u32, _s: bool) -> InodeRef { StaticFileInode::new(b"/autogroup-1 nice 0\n") }
fn pc_uid_map(t: u32, _s: bool) -> InodeRef { crate::userns_idmap::make(t, nscg::user_ns::IdMapKind::Uid) }
fn pc_gid_map(t: u32, _s: bool) -> InodeRef { crate::userns_idmap::make(t, nscg::user_ns::IdMapKind::Gid) }
fn pc_setgroups(t: u32, _s: bool) -> InodeRef { crate::userns_idmap::make_setgroups(t) }
fn pc_syscall(_t: u32, _s: bool) -> InodeRef { StaticFileInode::new(b"running\n") }
fn pc_empty(_t: u32, _s: bool) -> InodeRef { StaticFileInode::new(b"") }
fn pc_mounts(t: u32, is_self: bool) -> InodeRef {
    crate::mounts::make_proc_mounts(if is_self { None } else { Some(t) })
}
fn pc_mountinfo(t: u32, is_self: bool) -> InodeRef {
    crate::mounts::make_proc_mountinfo(if is_self { None } else { Some(t) })
}
fn pc_cgroup(t: u32, _s: bool) -> InodeRef { crate::make_proc_cgroup(Some(t)) }
fn pc_auxv(_t: u32, _s: bool) -> InodeRef { StaticFileInode::new(&[0u8; 16]) }
fn pc_timerslack(_t: u32, _s: bool) -> InodeRef { StaticFileInode::new(b"50000\n") }
fn pc_coredump_filter(_t: u32, _s: bool) -> InodeRef { StaticFileInode::new(b"00000033\n") }
fn pc_timens_offsets(t: u32, _s: bool) -> InodeRef { crate::timens_offsets::make(t) }
fn pc_exe(t: u32, _s: bool) -> InodeRef { crate::proc_links::make_proc_pid_exe(t) }
fn pc_cwd(t: u32, _s: bool) -> InodeRef { crate::proc_links::make_proc_pid_cwd(t) }
fn pc_root(t: u32, _s: bool) -> InodeRef { crate::proc_links::make_proc_pid_root(t) }
fn pc_fd(t: u32, is_self: bool) -> InodeRef { make_proc_fd_dir(if is_self { None } else { Some(t) }) }
fn pc_fdinfo(t: u32, is_self: bool) -> InodeRef { crate::fdinfo::make_fdinfo_dir(if is_self { None } else { Some(t) }) }
fn pc_attr(t: u32, _s: bool) -> InodeRef { make_proc_pid_attr_dir(t) }

const PID_ENTRIES: &[(&str, FileType, PidCtor)] = &[
    ("status", FileType::Regular, pc_status),
    ("cmdline", FileType::Regular, pc_cmdline),
    ("stat", FileType::Regular, pc_stat),
    ("maps", FileType::Regular, pc_maps),
    ("smaps", FileType::Regular, pc_smaps),
    ("smaps_rollup", FileType::Regular, pc_smaps),
    ("numa_maps", FileType::Regular, pc_maps),
    ("comm", FileType::Regular, pc_comm),
    ("environ", FileType::Regular, pc_environ),
    ("statm", FileType::Regular, pc_statm),
    ("wchan", FileType::Regular, pc_wchan),
    ("oom_score", FileType::Regular, pc_oom_score),
    ("oom_score_adj", FileType::Regular, pc_oom_score_adj),
    ("loginuid", FileType::Regular, pc_loginuid),
    ("sessionid", FileType::Regular, pc_sessionid),
    ("io", FileType::Regular, pc_io),
    ("limits", FileType::Regular, pc_limits),
    ("personality", FileType::Regular, pc_personality),
    ("sched", FileType::Regular, pc_sched),
    ("schedstat", FileType::Regular, pc_schedstat),
    ("autogroup", FileType::Regular, pc_autogroup),
    ("uid_map", FileType::Regular, pc_uid_map),
    ("gid_map", FileType::Regular, pc_gid_map),
    ("setgroups", FileType::Regular, pc_setgroups),
    ("syscall", FileType::Regular, pc_syscall),
    ("stack", FileType::Regular, pc_empty),
    ("mounts", FileType::Regular, pc_mounts),
    ("mountinfo", FileType::Regular, pc_mountinfo),
    ("mountstats", FileType::Regular, pc_empty),
    ("cgroup", FileType::Regular, pc_cgroup),
    ("auxv", FileType::Regular, pc_auxv),
    ("timerslack_ns", FileType::Regular, pc_timerslack),
    ("coredump_filter", FileType::Regular, pc_coredump_filter),
    ("timens_offsets", FileType::Regular, pc_timens_offsets),
    ("exe", FileType::Symlink, pc_exe),
    ("cwd", FileType::Symlink, pc_cwd),
    ("root", FileType::Symlink, pc_root),
    ("fd", FileType::Directory, pc_fd),
    ("fdinfo", FileType::Directory, pc_fdinfo),
    ("attr", FileType::Directory, pc_attr),
];

fn proc_pid_dir_lookup(d: &ProcPidDirInode, name: &str) -> KResult<InodeRef> {
    let tid = if d.is_self {
        if let Some(i) = crate::reg::proc_reg().lookup_path(&format!("self/{name}")) {
            return Ok(i);
        }
        sched::live::current().map(|c| c.tid).ok_or(VfsError::Enoent)?
    } else {
        d.tid
    };
    if let Some((_, _, ctor)) = PID_ENTRIES.iter().find(|(n, _, _)| *n == name) {
        return Ok(ctor(tid, d.is_self));
    }
    match name {
        "task" if d.allow_task_dir => {
            let task = sched::live::registry::lookup(tid).ok_or(VfsError::Enoent)?;
            let tgid = task.tgid.load(Ordering::Acquire);
            Ok(make_proc_pid_task_dir(tgid))
        }
        "ns" => Ok(make_proc_pid_ns_dir(tid)),
        "projid_map" => Ok(crate::sysctl::SysctlInode::new(b"         0          0 4294967295\n")),
        "make-it-fail" | "fail-nth" | "pagemap" | "kpagecount" | "kpageflags" => {
            Ok(StaticFileInode::new(b""))
        }
        "wakeups_count" => Ok(StaticFileInode::new(b"0\n")),
        _ => Err(VfsError::Enoent),
    }
}

struct ProcPidDirOps;

impl InodeOps for ProcPidDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<ProcPidDirInode>().ok_or(VfsError::Einval)?;
        proc_pid_dir_lookup(d, name)
    }
}

impl FileOps for ProcPidDirOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let d = inode.private::<ProcPidDirInode>().ok_or(VfsError::Einval)?;
        let mut idx = ctx.pos as usize;
        let total = PID_ENTRIES.len() + usize::from(d.allow_task_dir);
        while idx < total {
            let next = idx as u64 + 1;
            let (name, ft) = if idx < PID_ENTRIES.len() {
                let (n, ft, _) = PID_ENTRIES[idx];
                (n, ft)
            } else {
                ("task", FileType::Directory)
            };
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, ft, next) {
                return Ok(());
            }
            idx += 1;
        }
        Ok(())
    }
}

pub fn make_proc_pid_dir(tid: u32, is_self: bool, allow_task_dir: bool) -> InodeRef {
    InodeBuilder::new(
        pid_ino(0x01, tid),
        mk_mode(FileType::Directory, 0o555),
        Arc::new(ProcPidDirOps),
        Arc::new(ProcPidDirOps),
    )
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
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let d = inode.private::<ProcPidTaskDirInode>().ok_or(VfsError::Einval)?;
        let tids = sched::live::registry::thread_entries(d.tgid);
        let mut idx = ctx.pos as usize;
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
            let s = crate::util::decimal_str(&buf, n);
            let ino = inode.lookup(s).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(s, ino, FileType::Directory, next) {
                return Ok(());
            }
            idx += 1;
        }
        Ok(())
    }
}

pub fn make_proc_pid_task_dir(tgid: u32) -> InodeRef {
    InodeBuilder::new(
        pid_ino(0x07, tgid),
        mk_mode(FileType::Directory, 0o555),
        Arc::new(ProcPidTaskDirOps),
        Arc::new(ProcPidTaskDirOps),
    )
    .private(Arc::new(ProcPidTaskDirInode { tgid }))
    .build()
}

pub(crate) fn pid_to_kernel_tid(p: u32) -> Option<u32> {
    use sched::live::registry::{lookup, lookup_by_vpid};
    lookup_by_vpid(p).or_else(|| lookup(p)).map(|t| t.tid)
}
