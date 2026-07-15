use alloc::sync::Arc;

use syscall::errno::Errno;

/// Promote TIME-for-children at exec after freezing its offsets. # C: O(log N)
pub(crate) fn promote_time_namespace_at_exec(task: &sched::Task) -> Result<(), Errno> {
    let snapshot = task.namespace_snapshot().ok_or(Errno::Eio)?;
    if Arc::ptr_eq(&snapshot.time, &snapshot.time_for_children) { return Ok(()); }

    nscg::time_ns::freeze(&snapshot.time_for_children).map_err(|_| Errno::Eio)?;
    let promoted = Arc::clone(&snapshot.time_for_children);
    task.replace_time_namespace_pair(promoted, snapshot.time_for_children)
        .map_err(|_| Errno::Eio)
}

#[cfg(test)]
mod tests {
    use super::*;
    use namespace_identity::{NamespaceKind, NamespaceRef};
    use sched::{SchedClass, Task};

    fn task(tid: u32) -> Task {
        Task::new(tid, "exec-time", SchedClass::Normal { weight: 1024 })
    }

    fn time_owner() -> NamespaceRef {
        namespace_identity::allocate(NamespaceKind::Time,
            namespace_identity::initial(NamespaceKind::User), None).unwrap()
    }

    #[test]
    fn exec_promotes_for_children_and_freezes_offsets() {
        let task = task(901);
        let target = time_owner();
        nscg::time_ns::clone_from(&target,
            &namespace_identity::initial(NamespaceKind::Time)).unwrap();
        assert!(task.replace_time_namespace_for_children(Arc::clone(&target)).is_ok());

        promote_time_namespace_at_exec(&task).unwrap();

        let snapshot = task.namespace_snapshot().unwrap();
        assert!(Arc::ptr_eq(&snapshot.time, &target));
        assert!(Arc::ptr_eq(&snapshot.time_for_children, &target));
        assert!(nscg::time_ns::snapshot(&target).unwrap().frozen);
        assert_eq!(nscg::time_ns::set_offsets(&target, &[]),
            Err(nscg::time_ns::TimeNsError::Frozen));
    }

    #[test]
    fn exec_keeps_an_already_current_time_namespace() {
        let task = task(902);
        let initial = namespace_identity::initial(NamespaceKind::Time);

        promote_time_namespace_at_exec(&task).unwrap();

        let snapshot = task.namespace_snapshot().unwrap();
        assert!(Arc::ptr_eq(&snapshot.time, &initial));
        assert!(Arc::ptr_eq(&snapshot.time_for_children, &initial));
    }

    #[test]
    fn missing_time_state_does_not_publish_target_as_current() {
        let task = task(903);
        let target = time_owner();
        assert!(task.replace_time_namespace_for_children(Arc::clone(&target)).is_ok());

        assert_eq!(promote_time_namespace_at_exec(&task), Err(Errno::Eio));

        let snapshot = task.namespace_snapshot().unwrap();
        assert!(snapshot.time.is_initial());
        assert!(Arc::ptr_eq(&snapshot.time_for_children, &target));
    }
}
