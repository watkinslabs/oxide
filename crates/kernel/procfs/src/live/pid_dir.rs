use alloc::format;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use core::sync::atomic::Ordering;
use vfs::{DirContext, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError, mk_mode};

use super::ns_dir::make_proc_pid_ns_dir;
use super::pid_attr::make_proc_pid_attr_dir;
use super::{make_pid_oom_score, make_pid_oom_score_adj};
use super::pid_files::{
    make_pid_auxv, make_pid_cmdline, make_pid_comm, make_pid_environ, make_pid_io, make_pid_limits, make_pid_maps,
    make_pid_personality, make_pid_sched, make_pid_stat, make_pid_statm, make_pid_status,
};
use super::pid_ino;
use super::self_files::make_proc_fd_dir;
use crate::StaticFileInode;

pub struct ProcPidDirInode {
    pub tid: u32,
    pub is_self: bool,
    pub allow_task_dir: bool,
    /// The task this directory WAS built for (Linux: the inode's `struct pid`).
    /// Identity, not a lookup key: `d_revalidate`/`d_delete` upgrade it to ask
    /// "is my task still alive" without the registry lock and without trusting a
    /// tid that may since have been recycled onto a different task.
    pub task: Weak<sched::Task>,
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
fn pc_personality(t: u32, _s: bool) -> InodeRef { make_pid_personality(t) }
fn pc_sched(t: u32, _s: bool) -> InodeRef { make_pid_sched(t) }
fn pc_schedstat(_t: u32, _s: bool) -> InodeRef { StaticFileInode::new(b"0 0 0\n") }
fn pc_autogroup(_t: u32, _s: bool) -> InodeRef { StaticFileInode::new(b"/autogroup-1 nice 0\n") }
fn pc_uid_map(t: u32, _s: bool) -> InodeRef { crate::userns_idmap::make(t, nscg::user_ns::IdMapKind::Uid) }
fn pc_gid_map(t: u32, _s: bool) -> InodeRef { crate::userns_idmap::make(t, nscg::user_ns::IdMapKind::Gid) }
fn pc_projid_map(t: u32, _s: bool) -> InodeRef { crate::userns_idmap::make(t, nscg::user_ns::IdMapKind::Projid) }
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
fn pc_auxv(t: u32, _s: bool) -> InodeRef { make_pid_auxv(t) }
fn pc_timerslack(_t: u32, _s: bool) -> InodeRef { StaticFileInode::new(b"50000\n") }
fn pc_coredump_filter(_t: u32, _s: bool) -> InodeRef { StaticFileInode::new(b"00000033\n") }
fn pc_timens_offsets(t: u32, _s: bool) -> InodeRef { crate::timens_offsets::make(t) }
fn pc_exe(t: u32, _s: bool) -> InodeRef { crate::proc_links::make_proc_pid_exe(t) }
fn pc_cwd(t: u32, _s: bool) -> InodeRef { crate::proc_links::make_proc_pid_cwd(t) }
fn pc_root(t: u32, _s: bool) -> InodeRef { crate::proc_links::make_proc_pid_root(t) }
fn pc_fd(t: u32, is_self: bool) -> InodeRef { make_proc_fd_dir(if is_self { None } else { Some(t) }) }
fn pc_fdinfo(t: u32, is_self: bool) -> InodeRef { crate::fdinfo::make_fdinfo_dir(if is_self { None } else { Some(t) }) }
fn pc_attr(t: u32, _s: bool) -> InodeRef { make_proc_pid_attr_dir(t) }

/// `/proc/<tgid>/task` — present only on a thread-group leader's directory
/// (Linux `tgid_base_stuff` vs `tid_base_stuff`).
const TASK_DIR: &str = "task";

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
    ("projid_map", FileType::Regular, pc_projid_map),
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
    let inode = pid_entry_inode(d, tid, name)?;
    // Linux `pid_update_inode`: the per-pid inode is synthesized on every
    // lookup, so its mode (`tgid_base_stuff`) and its `task_dump_owner`
    // ownership are stamped here rather than baked into each constructor.
    super::pid_access::pid_update_inode(tid, name, &inode);
    Ok(inode)
}

fn pid_entry_inode(d: &ProcPidDirInode, tid: u32, name: &str) -> KResult<InodeRef> {
    if let Some((_, _, ctor)) = PID_ENTRIES.iter().find(|(n, _, _)| *n == name) {
        return Ok(ctor(tid, d.is_self));
    }
    match name {
        TASK_DIR if d.allow_task_dir => {
            let task = sched::live::registry::lookup(tid).ok_or(VfsError::Enoent)?;
            let tgid = task.tgid.load(Ordering::Acquire);
            Ok(make_proc_pid_task_dir(tgid))
        }
        "ns" => Ok(make_proc_pid_ns_dir(tid)),
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
    /// Every entry is synthesized on lookup, so a name whose constructor now
    /// fails (the task exited between two `getdents` pages) is dropped rather
    /// than emitted with `d_ino == 0`. # C: O(N log N)
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let d = inode.private::<ProcPidDirInode>().ok_or(VfsError::Einval)?;
        let mut names: Vec<(String, FileType)> =
            PID_ENTRIES.iter().map(|(n, ft, _)| (String::from(*n), *ft)).collect();
        if d.allow_task_dir { names.push((String::from(TASK_DIR), FileType::Directory)); }
        crate::readdir::emit_resolved(names, |n| inode.lookup(n).ok().map(|i| i.ino()), ctx)
    }
}

pub fn make_proc_pid_dir(tid: u32, is_self: bool, allow_task_dir: bool) -> InodeRef {
    let inode = InodeBuilder::new(
        pid_ino(0x01, tid),
        mk_mode(FileType::Directory, crate::pid_file_policy::MODE_DIR_RUGO),
        Arc::new(ProcPidDirOps),
        Arc::new(ProcPidDirOps),
    )
    .private(Arc::new(ProcPidDirInode {
        tid, is_self, allow_task_dir,
        task: sched::live::registry::lookup(tid).map(|t| Arc::downgrade(&t)).unwrap_or_default(),
    }))
    .build();
    // `task_dump_owner` exempts the `S_IFDIR|S_IRUGO|S_IXUGO` per-pid directory
    // from the non-dumpable clamp: `stat /proc/<pid>` reports the task's euid
    // even for a task whose files are root-owned.
    super::pid_access::pid_update_dir_inode(tid, &inode);
    inode
}

pub struct ProcPidTaskDirInode {
    pub tgid: u32,
    /// The thread-group leader this `task/` directory belongs to; see
    /// [`ProcPidDirInode::task`].
    pub task: Weak<sched::Task>,
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
    /// The thread set is re-snapshotted per call; a thread exiting mid-listing
    /// must not shift its siblings' cursors. # C: O(N log N)
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let d = inode.private::<ProcPidTaskDirInode>().ok_or(VfsError::Einval)?;
        let names = sched::live::registry::thread_entries(d.tgid).into_iter()
            .map(|(vtid, _)| (crate::readdir::decimal_name(vtid), FileType::Directory));
        crate::readdir::emit_resolved(names, |n| inode.lookup(n).ok().map(|i| i.ino()), ctx)
    }
}

pub fn make_proc_pid_task_dir(tgid: u32) -> InodeRef {
    InodeBuilder::new(
        pid_ino(0x07, tgid),
        mk_mode(FileType::Directory, crate::pid_file_policy::MODE_DIR_RUGO),
        Arc::new(ProcPidTaskDirOps),
        Arc::new(ProcPidTaskDirOps),
    )
    .private(Arc::new(ProcPidTaskDirInode {
        tgid,
        task: sched::live::registry::lookup(tgid).map(|t| Arc::downgrade(&t)).unwrap_or_default(),
    }))
    .build()
}

pub(crate) fn pid_to_kernel_tid(p: u32) -> Option<u32> {
    use sched::live::registry::{lookup, lookup_by_vpid, reader_pid_ns};
    // The internal-tid fallback names the kernel threads that never took a
    // visible number. It is the INITIAL namespace's view only: a reader inside
    // a nested namespace must not be able to reach a task by an identifier its
    // namespace never issued.
    let fallback = || if reader_pid_ns().is_initial() { lookup(p) } else { None };
    lookup_by_vpid(p).or_else(fallback).map(|t| t.tid)
}
