// Unpublished native child executable identity, shared with canonical procfs readers.
extern crate alloc;
use alloc::string::String;

/// Publish image metadata before the child enters the task registry.
/// # C: O(image_path.len())
pub(super) fn publish(child: &sched::Task, image_path: &str) {
    child.set_exe_path(Some(String::from(image_path)));
    // SAFETY: the caller owns this unpublished child's prepared address space;
    // no concurrent exec can replace its mm while identity is being installed.
    if let Some(mm) = unsafe { child.mm_ref() } { mm.set_exe_path(String::from(image_path)); }
    child.set_comm_exec(image_path.rsplit('/').next().unwrap_or(image_path));
}
