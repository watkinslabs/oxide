use alloc::fmt::Write;
use alloc::string::String;
use alloc::vec::Vec;

use vfs::KResult;

use crate::state::{
    TREE, migrate_task, notify_events_chain, visible_pid, visible_tid,
};

/// Read a control file `(cgid, file)`.
/// # C: O(subtree) for populated/pids; O(members) for procs
pub fn read_file(cgid: u64, file: &str) -> KResult<Vec<u8>> {
    if file == "cgroup.procs" {
        let tree = TREE.lock();
        let mut out = String::new();
        for pid in tree.direct_procs(cgid)? {
            let _ = writeln!(out, "{}", visible_pid(pid));
        }
        return Ok(out.into_bytes());
    }
    if file == "cgroup.threads" {
        let tree = TREE.lock();
        let mut out = String::new();
        for tid in tree.direct_threads(cgid)? {
            let _ = writeln!(out, "{}", visible_tid(tid));
        }
        return Ok(out.into_bytes());
    }
    TREE.lock().read_file(cgid, file)
}

/// Migrate the existing process named by `vpid`. # C: O(tasks)
pub fn attach_into(cgid: u64, vpid: u64) -> KResult<()> {
    let src = migrate_task(vpid, cgid, false)?;
    if src != cgid { notify_events_chain(src); }
    notify_events_chain(cgid);
    Ok(())
}

/// Place an unpublished child task into `cgid`. # C: O(threads)
pub fn attach_tid_into(cgid: u64, tid: u64) -> KResult<()> {
    let src = {
        let mut tree = TREE.lock();
        let src = tree.cgroup_of(tid);
        tree.add_proc(cgid, tid)?;
        src
    };
    if src != cgid { notify_events_chain(src); }
    notify_events_chain(cgid);
    Ok(())
}

/// Move a live process and all its threads under one hierarchy lock.
/// Scheduler migration serialization supplies the process leader identity.
/// # C: O(threads)
pub fn migrate_process(cgid: u64, tgid: u64) -> KResult<u64> {
    let mut tree = TREE.lock();
    let src = tree.cgroup_of(tgid);
    tree.add_proc(cgid, tgid)?;
    Ok(src)
}

/// Move one live thread within its current resource domain. # C: O(log n)
pub fn migrate_thread(cgid: u64, tid: u64) -> KResult<u64> {
    TREE.lock().move_thread(cgid, tid)
}
