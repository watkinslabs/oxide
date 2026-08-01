use alloc::sync::Arc;

use namespace_identity::{NamespaceKind, NamespaceRef};
use vfs::mntns::MntNamespaceRef;

use super::Task;
use crate::pid::PidMappingError;

/// One retained owner for every non-network namespace kind.
pub(crate) struct TaskNamespaces {
    cgroup: NamespaceRef,
    ipc: NamespaceRef,
    pid: NamespaceRef,
    pid_for_children: NamespaceRef,
    time: NamespaceRef,
    time_for_children: NamespaceRef,
    user: NamespaceRef,
    uts: NamespaceRef,
    mount: MntNamespaceRef,
}

/// Retained point-in-time task namespace set.
#[derive(Clone)]
pub struct TaskNamespaceSnapshot {
    pub cgroup: NamespaceRef,
    pub ipc: NamespaceRef,
    pub pid: NamespaceRef,
    pub pid_for_children: NamespaceRef,
    pub time: NamespaceRef,
    pub time_for_children: NamespaceRef,
    pub user: NamespaceRef,
    pub uts: NamespaceRef,
    pub mount: MntNamespaceRef,
}

impl TaskNamespaces {
    pub(super) fn initial() -> Self {
        Self {
            cgroup: namespace_identity::initial(NamespaceKind::Cgroup),
            ipc: namespace_identity::initial(NamespaceKind::Ipc),
            pid: namespace_identity::initial(NamespaceKind::Pid),
            pid_for_children: namespace_identity::initial(NamespaceKind::Pid),
            time: namespace_identity::initial(NamespaceKind::Time),
            time_for_children: namespace_identity::initial(NamespaceKind::Time),
            user: namespace_identity::initial(NamespaceKind::User),
            uts: namespace_identity::initial(NamespaceKind::Uts),
            mount: vfs::mntns::initial(),
        }
    }

    fn snapshot(&self) -> TaskNamespaceSnapshot {
        TaskNamespaceSnapshot {
            cgroup: self.cgroup.clone(), ipc: self.ipc.clone(),
            pid: self.pid.clone(),
            pid_for_children: self.pid_for_children.clone(),
            time: self.time.clone(),
            time_for_children: self.time_for_children.clone(),
            user: self.user.clone(), uts: self.uts.clone(),
            mount: Arc::clone(&self.mount),
        }
    }

    fn from_snapshot(snapshot: TaskNamespaceSnapshot) -> Self {
        Self {
            cgroup: snapshot.cgroup, ipc: snapshot.ipc, pid: snapshot.pid,
            pid_for_children: snapshot.pid_for_children, time: snapshot.time,
            time_for_children: snapshot.time_for_children,
            user: snapshot.user, uts: snapshot.uts, mount: snapshot.mount,
        }
    }

    fn replace(&mut self, namespace: NamespaceRef) -> Result<NamespaceRef, NamespaceRef> {
        let slot = match namespace.kind() {
            NamespaceKind::Cgroup => &mut self.cgroup,
            NamespaceKind::Ipc => &mut self.ipc,
            NamespaceKind::Pid => &mut self.pid,
            NamespaceKind::Time => &mut self.time,
            NamespaceKind::User => &mut self.user,
            NamespaceKind::Uts => &mut self.uts,
            NamespaceKind::Mnt | NamespaceKind::Net => return Err(namespace),
        };
        Ok(core::mem::replace(slot, namespace))
    }
}

impl Task {
    /// Retain the complete non-network namespace set atomically.
    /// # C: O(1)
    /// # Ctx: caller holds no lock ranked `Namespace` or higher
    /// # Lk: takes `Namespace` (rank 75)
    /// # Sleeps: no
    pub fn namespace_snapshot(&self) -> Option<TaskNamespaceSnapshot> {
        self.namespaces.lock().as_ref().map(TaskNamespaces::snapshot)
    }

    /// Replace the complete namespace set with a retained snapshot.
    /// # C: O(1) + final-owner drops
    /// # Ctx: caller holds no lock ranked `Namespace` or higher
    /// # Lk: takes `Namespace` (rank 75)
    /// # Sleeps: no
    pub fn replace_namespace_set(&self, snapshot: TaskNamespaceSnapshot)
        -> Result<(), TaskNamespaceSnapshot>
    {
        let replacement = TaskNamespaces::from_snapshot(snapshot);
        let old = {
            let mut slot = self.namespaces.lock();
            if slot.is_none() { return Err(replacement.snapshot()); }
            slot.replace(replacement)
        };
        drop(old);
        Ok(())
    }

    /// Replace one concrete non-mount namespace owner.
    /// # C: O(1) + final-owner drop
    /// # Ctx: caller holds no lock ranked `Namespace` or higher
    /// # Lk: takes `Namespace` (rank 75)
    /// # Sleeps: no
    pub fn replace_namespace(&self, namespace: NamespaceRef) -> Result<(), NamespaceRef> {
        let old = {
            let mut set = self.namespaces.lock();
            let Some(set) = set.as_mut() else { return Err(namespace); };
            set.replace(namespace)?
        };
        drop(old);
        Ok(())
    }

    /// Replace the concrete mount namespace owner.
    /// # C: O(1) + final-owner drop
    /// # Ctx: caller holds no lock ranked `Namespace` or higher
    /// # Lk: takes `Namespace` (rank 75)
    /// # Sleeps: no
    pub fn replace_mount_namespace(&self, namespace: MntNamespaceRef)
        -> Result<(), MntNamespaceRef>
    {
        let old = {
            let mut set = self.namespaces.lock();
            let Some(set) = set.as_mut() else { return Err(namespace); };
            core::mem::replace(&mut set.mount, namespace)
        };
        drop(old);
        Ok(())
    }

    /// Set the PID namespace inherited by the next child.
    /// # C: O(1) + final-owner drop
    pub fn replace_pid_namespace_for_children(&self, namespace: NamespaceRef)
        -> Result<(), NamespaceRef>
    {
        if namespace.kind() != NamespaceKind::Pid { return Err(namespace); }
        let old = {
            let mut set = self.namespaces.lock();
            let Some(set) = set.as_mut() else { return Err(namespace); };
            core::mem::replace(&mut set.pid_for_children, namespace)
        };
        drop(old);
        Ok(())
    }

    /// Retain the PID namespace inherited by a new child.
    /// # C: O(1)
    pub fn pid_namespace_for_children(&self) -> Option<NamespaceRef> {
        self.namespaces.lock().as_ref().map(|set| set.pid_for_children.clone())
    }

    /// Retain the TIME namespace inherited by a new child.
    /// # C: O(1)
    pub fn time_namespace_for_children(&self) -> Option<NamespaceRef> {
        self.namespaces.lock().as_ref().map(|set| set.time_for_children.clone())
    }

    /// Set the TIME namespace inherited by the next child.
    /// # C: O(1) + final-owner drop
    pub fn replace_time_namespace_for_children(&self, namespace: NamespaceRef)
        -> Result<(), NamespaceRef>
    {
        if namespace.kind() != NamespaceKind::Time { return Err(namespace); }
        let old = {
            let mut set = self.namespaces.lock();
            let Some(set) = set.as_mut() else { return Err(namespace); };
            core::mem::replace(&mut set.time_for_children, namespace)
        };
        drop(old);
        Ok(())
    }

    /// Replace current and for-children TIME namespace owners atomically.
    /// # C: O(1) + final-owner drops
    pub fn replace_time_namespace_pair(&self, current: NamespaceRef,
        for_children: NamespaceRef) -> Result<(), (NamespaceRef, NamespaceRef)>
    {
        if current.kind() != NamespaceKind::Time ||
            for_children.kind() != NamespaceKind::Time
        {
            return Err((current, for_children));
        }
        let old = {
            let mut set = self.namespaces.lock();
            let Some(set) = set.as_mut() else { return Err((current, for_children)); };
            let old_current = core::mem::replace(&mut set.time, current);
            let old_for_children = core::mem::replace(
                &mut set.time_for_children, for_children);
            (old_current, old_for_children)
        };
        drop(old);
        Ok(())
    }

    /// Freeze exact inner-to-outer PID numbers before registry publication.
    /// # C: O(depth)
    pub fn configure_pid_mappings(&self, numbers: &[u32]) -> Result<(), PidMappingError> {
        let namespace = self.namespace_owner(NamespaceKind::Pid)
            .ok_or(PidMappingError::NamespaceKind)?;
        self.pid.configure_mappings(&namespace, numbers)
    }

    /// Draw this task's number in its own PID namespace and in every ancestor,
    /// then stamp the own-namespace number as the visible thread id. `set_tid`
    /// names numbers innermost-first for a caller that picked them. The
    /// visible process id follows for a thread-group leader; a task joining an
    /// existing group keeps the leader's. # C: O(depth log N_held)
    pub fn alloc_pid_mappings(&self, set_tid: &[u32], group_leader: bool)
        -> Result<(), PidMappingError>
    {
        let namespace = self.namespace_owner(NamespaceKind::Pid)
            .ok_or(PidMappingError::NamespaceKind)?;
        let numbers = self.pid.alloc_mappings(&namespace, set_tid)?;
        let own = numbers[0];
        self.vtid.store(own, core::sync::atomic::Ordering::Release);
        if group_leader { self.vtgid.store(own, core::sync::atomic::Ordering::Release); }
        Ok(())
    }

    /// The number this task carries as seen from `namespace`; 0 when
    /// `namespace` does not number it. # C: O(depth)
    pub fn pid_nr_ns(&self, namespace: &NamespaceRef) -> u32 {
        self.pid.nr_in(namespace)
    }

    /// Configure ordinary initial-namespace tasks at publication. Nested PID
    /// namespaces require explicit ancestor numbers from clone setup. # C: O(1)
    pub(crate) fn configure_initial_pid_mapping(&self) {
        if self.pid.mappings_configured() { return; }
        let Some(namespace) = self.namespace_owner(NamespaceKind::Pid) else { return };
        if !namespace.is_initial() { return; }
        let nr = self.vtid.load(core::sync::atomic::Ordering::Acquire);
        let nr = if nr == 0 { self.tid } else { nr };
        let _ = self.pid.configure_mappings(&namespace, &[nr]);
    }

    /// Current namespace identity for `kind`.
    /// # C: O(1)
    pub fn namespace_id(&self, kind: NamespaceKind) -> Option<u64> {
        if kind == NamespaceKind::Mnt {
            return self.mount_namespace_snapshot()
                .map(|owner| owner.namespace_identity().id().as_u64());
        }
        if kind == NamespaceKind::Net {
            return self.network_namespace_snapshot()
                .map(|owner| owner.namespace_identity().id().as_u64());
        }
        let set = self.namespaces.lock();
        let set = set.as_ref()?;
        Some(match kind {
            NamespaceKind::Cgroup => set.cgroup.id().as_u64(),
            NamespaceKind::Ipc => set.ipc.id().as_u64(),
            NamespaceKind::Pid => set.pid.id().as_u64(),
            NamespaceKind::Time => set.time.id().as_u64(),
            NamespaceKind::User => set.user.id().as_u64(),
            NamespaceKind::Uts => set.uts.id().as_u64(),
            NamespaceKind::Mnt | NamespaceKind::Net => unreachable!(),
        })
    }

    /// Retain one concrete non-mount namespace owner.
    /// # C: O(1)
    pub fn namespace_owner(&self, kind: NamespaceKind) -> Option<NamespaceRef> {
        if matches!(kind, NamespaceKind::Mnt | NamespaceKind::Net) { return None; }
        let set = self.namespaces.lock();
        let set = set.as_ref()?;
        Some(match kind {
            NamespaceKind::Cgroup => &set.cgroup, NamespaceKind::Ipc => &set.ipc,
            NamespaceKind::Pid => &set.pid, NamespaceKind::Time => &set.time,
            NamespaceKind::User => &set.user, NamespaceKind::Uts => &set.uts,
            NamespaceKind::Mnt | NamespaceKind::Net => unreachable!(),
        }.clone())
    }

    /// Current mount namespace identity.
    /// # C: O(1)
    pub fn mount_namespace_id(&self) -> Option<u64> {
        self.namespaces.lock().as_ref().map(|set| set.mount.id())
    }


    /// Retain the concrete current mount namespace owner.
    /// # C: O(1)
    pub fn mount_namespace_snapshot(&self) -> Option<MntNamespaceRef> {
        self.namespaces.lock().as_ref().map(|set| Arc::clone(&set.mount))
    }

    /// Release every non-network namespace owner before zombie publication.
    /// # C: O(1) + final-owner drops
    pub fn release_namespaces(&self) {
        let old = self.namespaces.lock().take();
        drop(old);
    }
}
