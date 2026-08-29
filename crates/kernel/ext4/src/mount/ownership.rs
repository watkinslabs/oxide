use alloc::sync::Arc;

use super::Mount;

impl Mount {
    /// Return the stable sleepable owner for one allocation group.
    /// # C: O(log N) first use; O(log N) lookup
    pub(crate) fn group_lock(&self, group: u32) -> Arc<sched::live::Mutex<()>> {
        let mut locks = self.group_locks.lock();
        Arc::clone(locks.entry(group).or_insert_with(|| Arc::new(sched::live::Mutex::new(()))))
    }
}
