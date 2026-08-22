use syscall::errno::Errno;

use crate::clone_abi::CloneCaller;

pub(super) fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Publish a nominated child tid best-effort. # C: O(1)
pub(super) fn put_tid_best_effort(uaddr: u64, tid: u32) {
    if uaddr == 0 { return; }
    let _ = uaccess::copy_to_user(uaddr, &(tid as i32).to_le_bytes());
}

/// Facts about the running task the shared validation ladder needs.
/// # C: O(pid-ns depth)
pub(super) fn caller_facts(cur: &sched::Task) -> CloneCaller {
    CloneCaller { is_ns_init: sched::live::zombies::is_namespace_init(cur) }
}

/// Validate and reserve clone3 set_tid values. # C: O(N_requested × N_tasks)
pub(crate) fn set_requested_pids_ok(requested: &[u32]) -> Result<(), Errno> {
    use namespace_identity::NamespaceKind;
    let cur = sched::live::current().ok_or(Errno::Esrch)?;
    let mut level = cur.namespace_owner(NamespaceKind::Pid).map(|ns| ns.pin());
    let mut depth = 0usize;
    while let Some(ns) = level { depth += 1; level = ns.parent(); }
    crate::clone_abi::set_tid_values_ok(requested, depth + 1)?;
    let user_ns = cur.namespace_owner(NamespaceKind::User).ok_or(Errno::Esrch)?;
    if !nscg::proc_ns::has_cap_for(cur, &user_ns.pin(), sched::cap::SYS_ADMIN) {
        return Err(Errno::Eperm);
    }
    let mut level = cur.namespace_owner(NamespaceKind::Pid);
    for pid in requested {
        let Some(here) = level else { break };
        if sched::registry::lookup_in_namespace(&here, *pid).is_some() {
            return Err(Errno::Eexist);
        }
        level = here.parent().and_then(|parent| parent.get_active());
    }
    Ok(())
}

pub(super) fn user_i32_ptr_ok(p: u64) -> bool {
    p != 0 && uaccess::access_ok(p, core::mem::size_of::<i32>())
}
