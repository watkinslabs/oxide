// `access_ok`'s tagged-pointer question, answered by the owner of the flag.
//
// `uaccess` is below `sched` in the crate graph, so it cannot read
// `Task::tagged_addr` directly. Shadowing the flag into a per-CPU word there
// instead would create a second copy of the truth that a context switch or an
// exec could leave stale — precisely the split this project forbids.

/// Non-zero when a user pointer's top byte is a tag for the current context.
///
/// Answers "yes" when there is no current task: that is a kernel thread
/// operating on a borrowed mm, whose owning process holds the flag. Linux
/// reads the same case as `current->flags & PF_KTHREAD` and untags
/// unconditionally, because asynchronous I/O run on behalf of a tagging
/// process must not reject the pointers that process supplied.
///
/// # SAFETY: reads one atomic on the current task; takes no locks and cannot
/// re-enter `uaccess`.
/// # C: O(1)
#[no_mangle]
pub unsafe extern "C" fn oxide_untag_user_pointers() -> u64 {
    match crate::live::current() {
        Some(cur) => cur.tagged_addr.load(core::sync::atomic::Ordering::Acquire) as u64,
        None => 1,
    }
}
