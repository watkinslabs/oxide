//! Immutable socket creation identity shared with asynchronous transport state.

use alloc::sync::Arc;

use cgroup::CgroupBpfRuntime;
use network_namespace::NetworkNamespaceRef;

/// Namespace, credential, and cgroup policy identity pinned when a socket is created.
pub struct SocketOwner {
    pub net_namespace: NetworkNamespaceRef,
    pub owner_uid: u32,
    pub cgroup: Arc<CgroupBpfRuntime>,
}

impl SocketOwner {
    /// Capture the current task's effective UID and canonical cgroup runtime. # C: O(log cgroups)
    #[cfg(target_os = "oxide-kernel")]
    pub fn current(net_namespace: NetworkNamespaceRef) -> Arc<Self> {
        let Some(task) = sched::live::current() else {
            return Self::root(net_namespace, 0);
        };
        let owner_uid = task.creds.euid.load(core::sync::atomic::Ordering::Acquire);
        Arc::new(Self {
            net_namespace,
            owner_uid,
            cgroup: cgroup::bpf::runtime_for_task(task.tid as u64),
        })
    }

    /// Build a hosted or kernel-context owner rooted in the default cgroup. # C: O(1)
    pub fn root(net_namespace: NetworkNamespaceRef, owner_uid: u32) -> Arc<Self> {
        Arc::new(Self {
            net_namespace,
            owner_uid,
            cgroup: cgroup::bpf::root_runtime(),
        })
    }

    /// Derive the short-lived namespace table key. # C: O(1)
    pub fn net_ns(&self) -> u64 { crate::net_ns::namespace_id(&self.net_namespace) }
}

#[cfg(not(target_os = "oxide-kernel"))]
impl SocketOwner {
    /// Hosted socket identity uses the root cgroup runtime. # C: O(1)
    pub fn current(net_namespace: NetworkNamespaceRef) -> Arc<Self> {
        Self::root(net_namespace, 0)
    }
}
