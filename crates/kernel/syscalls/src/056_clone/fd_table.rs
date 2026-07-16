use alloc::sync::Arc;

use super::CLONE_FILES;

/// Inherit the caller's descriptor table under Linux clone semantics.
/// # C: O(open fds) without `CLONE_FILES`; O(1) with it
pub(super) fn inherit(parent: &sched::Task, child: &sched::Task, flags: u64) {
    // SAFETY: caller is current; child is unpublished and has one mutator.
    let Some(parent_fdt) = (unsafe { parent.fd_table_ref().cloned() }) else { return; };
    let child_fdt = if (flags & CLONE_FILES) != 0 {
        Arc::clone(&parent_fdt)
    } else {
        Arc::new(parent_fdt.fork_clone())
    };
    #[cfg(feature = "debug-fdlife")]
    crate::fd_life::clone(parent, child, flags, &parent_fdt, &child_fdt);
    // SAFETY: child is unpublished; clone path is its only fd-table writer.
    unsafe { child.replace_fd_table(Some(child_fdt)); }
}
