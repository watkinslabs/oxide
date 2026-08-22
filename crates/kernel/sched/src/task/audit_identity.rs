// Per-task audit login identity. Procfs is the sole setter; every producer
// reads this owner so records and `/proc/<pid>` cannot diverge.

use core::sync::atomic::Ordering;

use super::Task;

impl Task {
    /// Snapshot login uid and session id in publication order. # C: O(1)
    pub fn audit_identity(&self) -> (u32, u32) {
        let word = self.audit_identity.load(Ordering::Acquire);
        ((word >> 32) as u32, word as u32)
    }

    /// Publish a successfully admitted login identity. # C: O(1)
    pub fn set_audit_identity(&self, login: u32, session: u32) {
        self.audit_identity.store(((login as u64) << 32) | session as u64,
            Ordering::Release);
    }

    /// `dup_task_struct` copies both audit identity fields. # C: O(1)
    pub fn inherit_audit_identity(&self, parent: &Task) {
        let (login, session) = parent.audit_identity();
        self.set_audit_identity(login, session);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SchedClass;

    fn task(tid: u32) -> Task {
        Task::new(tid, "audit-id", SchedClass::Normal { weight: 1024 })
    }

    #[test]
    fn a_fresh_task_has_no_login_identity() {
        assert_eq!(task(1).audit_identity(), (u32::MAX, u32::MAX));
    }

    #[test]
    fn a_fork_copies_both_fields_and_then_diverges() {
        let parent = task(2);
        parent.set_audit_identity(1000, 7);
        let child = task(3);
        child.inherit_audit_identity(&parent);
        assert_eq!(child.audit_identity(), (1000, 7));
        child.set_audit_identity(1001, 8);
        assert_eq!(parent.audit_identity(), (1000, 7));
    }
}
