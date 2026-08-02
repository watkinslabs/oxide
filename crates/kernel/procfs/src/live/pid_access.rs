// Kernel-side application of `crate::pid_file_policy` to a freshly built
// per-pid `/proc` inode: Linux `pid_update_inode` (owner + mode) plus the
// `ptrace_may_access` content gate the `S_IRUSR` entries carry.
//
// Every decision lives in the ungated `pid_file_policy` module; this file only
// reads live task state and calls it.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use vfs::{FileOps, Ino, Inode, InodeBuilder, InodeRef, KResult, VfsError, default_inode_ops, mk_mode, FileType};

use crate::pid_file_policy::{dump_owner, is_world_searchable_dir, needs_ptrace_gate, pid_file_mode};

/// Linux `pid_update_inode`: stamp the entry's table mode and the owner
/// `task_dump_owner` computes. Called on every per-pid lookup because these
/// inodes are synthesized per lookup, exactly as Linux recomputes them in
/// `proc_pid_make_inode`. # C: O(1)
pub(crate) fn pid_update_inode(tid: u32, name: &str, inode: &InodeRef) {
    let mode = pid_file_mode(name);
    let _ = inode.set_perm(mode);
    let searchable = is_world_searchable_dir(inode.file_type() == FileType::Directory, mode);
    stamp_owner(tid, inode, searchable);
}

/// The per-pid DIRECTORY itself (`/proc/<pid>`, `/proc/<pid>/task/<tid>`),
/// which `task_dump_owner` exempts from the non-dumpable clamp. # C: O(1)
pub(crate) fn pid_update_dir_inode(tid: u32, inode: &InodeRef) {
    stamp_owner(tid, inode, true);
}

/// # C: O(1)
fn stamp_owner(tid: u32, inode: &InodeRef, is_pid_dir: bool) {
    let Some(task) = sched::live::registry::lookup(tid) else { return };
    let (uid, gid) = dump_owner(
        task.clone_mm().is_none(),
        task.creds.euid.load(Ordering::Acquire),
        task.creds.egid.load(Ordering::Acquire),
        task.dumpable.load(Ordering::Acquire),
        is_pid_dir,
    );
    let _ = inode.set_owner(uid, gid);
}

/// Linux `ptrace_may_access(task, PTRACE_MODE_*_FSCREDS)` for a `/proc` access —
/// FSCREDS because the caller arrived through a filesystem syscall. A missing
/// current task (early boot / kthread) is the in-kernel reader, which is always
/// allowed; a vanished target is `ESRCH`, as `get_proc_task` returns.
/// # C: O(1)
pub(crate) fn ptrace_may_access(tid: u32) -> KResult<()> {
    let Some(cur) = sched::live::current() else { return Ok(()) };
    let Some(target) = sched::live::registry::lookup(tid) else { return Err(VfsError::Esrch) };
    match sched::ptrace_access::may_access_mode(cur, &target, sched::ptrace_access::Mode::FsCreds) {
        Ok(()) => Ok(()),
        Err(_) => Err(VfsError::Eperm),
    }
}

/// `i_private` of a ptrace-gated per-pid file. `entry` is the `tgid_base_stuff`
/// name, so the gate consults `pid_file_policy::needs_ptrace_gate` at read time
/// rather than each constructor carrying its own copy of that decision.
struct GatedData { tid: u32, entry: &'static str, gen: fn(u32) -> Vec<u8> }

struct GatedFileOps;

impl FileOps for GatedFileOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<GatedData>().ok_or(VfsError::Einval)?;
        if needs_ptrace_gate(d.entry) { ptrace_may_access(d.tid)?; }
        Ok(crate::dyn_file::read_at(&(d.gen)(d.tid), off, buf))
    }
    fn write(&self, _inode: &Inode, _off: u64, _buf: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
}

/// A `/proc/<pid>/<entry>` whose CONTENT is behind `ptrace_may_access` — Linux
/// `lock_trace()` / `proc_mem_open()`. The DAC mode alone cannot express this:
/// a same-uid caller must still be refused once the target became non-dumpable,
/// and a CAP_SYS_PTRACE holder must be admitted regardless of uid. `maps` and
/// `smaps` in particular are `S_IRUGO`, so this check is the ONLY thing keeping
/// another user's address-space layout private. # C: O(1)
pub fn make_pid_gated_file(ino: Ino, tid: u32, entry: &'static str, gen: fn(u32) -> Vec<u8>) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, pid_file_mode(entry)),
        default_inode_ops(), Arc::new(GatedFileOps))
        .private(Arc::new(GatedData { tid, entry, gen }))
        .build()
}

/// May this reader see `/proc/<pid>` on THIS mount, at the threshold the call
/// site cares about (Linux `has_pid_permissions`)?
///
/// Every decision is `crate::fs_info::has_pid_permissions`; this reads the two
/// live inputs it cannot: whether the reader is in the mount's `gid=` group
/// (`in_group_p`) and whether it could ptrace the target. Both are skipped when
/// `hidepid=off`, which is every mount that did not ask for confinement — the
/// gate must not put a task lookup and a ptrace walk on the default `/proc`
/// readdir path.
/// # C: O(1) for hidepid=off; O(groups) + O(ptrace check) otherwise
pub(crate) fn pid_visible(info: &crate::fs_info::ProcFsInfo, tid: u32,
                          min: crate::fs_info::HidePid) -> bool {
    if info.hide_pid == crate::fs_info::HidePid::Off { return true; }
    let in_group = match (info.pid_gid, sched::live::current()) {
        (Some(g), Some(cur)) => cur.creds.egid.load(core::sync::atomic::Ordering::Acquire) == g
            || cur.creds.group_list().is_some_and(|l| l.contains(&g)),
        _ => false,
    };
    crate::fs_info::has_pid_permissions(info, min, in_group, ptrace_may_access(tid).is_ok())
}
