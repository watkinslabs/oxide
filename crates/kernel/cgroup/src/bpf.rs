//! Public bridge to the cgroup-owned device-program state.
//!
//! Keeping these wrappers beside the hierarchy interface makes cgroup the
//! single owner of direct and effective attachment arrays.

use alloc::sync::Arc;

use vfs::InodeRef;

use crate::state::TREE;
use crate::tree::{BpfDeviceError, BpfDeviceMode, BpfDeviceQuery};

/// Cgroup target whose online state was checked at fd-resolution ordering.
///
/// Linux's retained cgroup/css reference does not make `rmdir` return EBUSY.
/// Oxide likewise permits removal after this check; the later hierarchy
/// mutation/query revalidates online state atomically and returns `Offline`
/// rather than acting on a stale identity.
pub struct DeviceTarget {
    cgid: u64,
}

impl DeviceTarget {
    /// Canonical hierarchy id of the pinned target. # C: O(1)
    pub fn cgid(&self) -> u64 { self.cgid }
}

/// Resolve an online cgroup identity at Linux's `cgroup_get_from_fd()` point.
/// # C: O(log nodes)
pub fn device_target(cgid: u64) -> Result<DeviceTarget, BpfDeviceError> {
    TREE.lock().bpf_device_require_online(cgid)?;
    Ok(DeviceTarget { cgid })
}

/// Attach a verified `BPF_PROG_TYPE_CGROUP_DEVICE` object directly to one
/// online cgroup.  The hierarchy retains the inode reference after the
/// userspace program fd closes. # C: O(descendants * effective programs)
pub fn device_attach(
    cgid: u64,
    prog: InodeRef,
    mode: BpfDeviceMode,
    replace: Option<&InodeRef>,
    expected_revision: u64,
) -> Result<(), BpfDeviceError> {
    TREE.lock().bpf_device_attach(cgid, prog, mode, replace, expected_revision)
}

/// Detach one exact device program from an online cgroup.
/// # C: O(descendants * effective programs)
pub fn device_detach(
    cgid: u64,
    prog: Option<&InodeRef>,
    expected_revision: u64,
) -> Result<(), BpfDeviceError> {
    TREE.lock().bpf_device_detach(cgid, prog, expected_revision)
}

/// Immutable effective device-program array for a task's current cgroup.
/// # C: O(log nodes)
pub fn device_effective(cgid: u64) -> Option<Arc<[InodeRef]>> {
    TREE.lock().bpf_device_effective(cgid)
}

/// Resolve a task membership and pin its effective device policy under one
/// hierarchy lock, so migration/removal cannot produce a torn snapshot.
/// # C: O(log nodes)
pub fn device_effective_for_task(tid: u64) -> Option<Arc<[InodeRef]>> {
    let tree = TREE.lock();
    let cgid = tree.cgroup_of(tid);
    tree.bpf_device_effective(cgid)
}

/// Direct/effective device-program query snapshot. # C: O(direct)
pub fn device_query(cgid: u64) -> Result<BpfDeviceQuery, BpfDeviceError> {
    TREE.lock().bpf_device_query(cgid)
}
