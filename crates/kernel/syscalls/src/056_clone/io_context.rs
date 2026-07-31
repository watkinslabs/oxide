use super::CLONE_IO;

/// Inherit the caller's I/O priority context under Linux clone semantics.
///
/// The fork path already gave the child an UNSHARED copy (clone flags do not
/// reach the spawn path). `CLONE_IO` replaces it with the parent's own
/// context, so a later `ioprio_set(2)` on either task is observed by both —
/// which is the whole point of the flag, and cannot be expressed by copying a
/// value.
/// # C: O(1)
pub(super) fn inherit(parent: &sched::Task, child: &sched::Task, flags: u64) {
    if (flags & CLONE_IO) == 0 { return; }
    child.set_io_context(parent.io_context());
}
