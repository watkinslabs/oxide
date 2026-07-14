use alloc::sync::Arc;

use network_namespace::{NetworkNamespaceId, NetworkNamespaceRef};

use super::{Task, TaskState};

impl Task {
    /// Clone the task's current network namespace owner atomically.
    /// # C: O(1)
    /// # Ctx: caller holds no lock ranked `Namespace` or higher
    /// # Lk: takes `Namespace` (rank 75)
    /// # Sleeps: no
    pub fn network_namespace_snapshot(&self) -> Option<NetworkNamespaceRef> {
        self.net_namespace.lock().as_ref().map(Arc::clone)
    }

    /// Read the stable identity of the task's current network namespace.
    /// # C: O(1)
    /// # Ctx: caller holds no lock ranked `Namespace` or higher
    /// # Lk: takes `Namespace` (rank 75)
    /// # Sleeps: no
    pub fn network_namespace_id(&self) -> Option<NetworkNamespaceId> {
        self.net_namespace.lock().as_ref().map(|namespace| namespace.id())
    }

    /// Replace network namespace membership and drop the old owner unlocked.
    /// # C: O(1) + final-owner drop
    /// # Ctx: caller holds no lock ranked `Namespace` or higher
    /// # Lk: takes `Namespace` (rank 75)
    /// # Sleeps: no
    pub fn replace_network_namespace(&self, namespace: NetworkNamespaceRef)
        -> Result<(), NetworkNamespaceRef>
    {
        let old = {
            let mut slot = self.net_namespace.lock();
            if slot.is_none() { return Err(namespace); }
            slot.replace(namespace)
        };
        drop(old);
        Ok(())
    }

    /// Release network namespace membership and drop the owner unlocked.
    /// # C: O(1) + final-owner drop
    /// # Ctx: caller holds no lock ranked `Namespace` or higher
    /// # Lk: takes `Namespace` (rank 75)
    /// # Sleeps: no
    pub fn release_network_namespace(&self) {
        let old = {
            let mut slot = self.net_namespace.lock();
            slot.take()
        };
        drop(old);
    }

    /// Release namespace membership before publishing terminal task state.
    /// # C: O(1) + final-owner drop
    /// # Ctx: caller holds no lock ranked `Namespace` or higher
    /// # Lk: takes `Namespace` (rank 75)
    /// # Sleeps: no
    pub(crate) fn mark_done(&self) {
        self.release_network_namespace();
        self.set_state(TaskState::Zombie);
    }
}
