/// Publish a new process's initial cgroup before the child can run.
/// # C: O(threads)
pub(crate) fn attach_new_process(
    cgid: Option<u64>,
    child_tid: u64,
    parent_tid: u64,
) -> Option<i64> {
    if let Some(cgid) = cgid {
        if let Err(error) = cgroup::attach_tid_into(cgid, child_tid) {
            return Some(crate::namei_common::errno_from_vfs(error));
        }
    } else {
        cgroup::inherit(child_tid, parent_tid);
    }
    None
}
