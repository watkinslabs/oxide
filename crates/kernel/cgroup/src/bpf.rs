//! Public bridge to cgroup-owned direct and effective BPF state.

use alloc::sync::Arc;

use vfs::InodeRef;

use crate::state::TREE;
use crate::tree::{
    BpfAttachError, BpfAttachMode, BpfAttachOrder, BpfAttachQuery, BpfDeviceError,
    BpfDeviceMode, BpfDeviceQuery, CgroupBpfAttachType, CgroupBpfRuntime,
};

/// Cgroup target whose online state was checked at fd-resolution ordering.
pub struct CgroupBpfTarget {
    cgid: u64,
}

impl CgroupBpfTarget {
    /// Canonical hierarchy id of the checked target. # C: O(1)
    pub fn cgid(&self) -> u64 { self.cgid }
}

pub type DeviceTarget = CgroupBpfTarget;

/// Resolve an online cgroup identity at `cgroup_get_from_fd()` ordering.
/// # C: O(log nodes)
pub fn target(cgid: u64) -> Result<CgroupBpfTarget, BpfAttachError> {
    TREE.lock().bpf_require_online(cgid)?;
    Ok(CgroupBpfTarget { cgid })
}

/// Validate an optimistic direct-list revision before relative-anchor lookup.
/// # C: O(log nodes)
pub fn check_revision(
    cgid: u64,
    attach_type: CgroupBpfAttachType,
    expected_revision: u64,
) -> Result<(), BpfAttachError> {
    TREE.lock().bpf_check_revision(cgid, attach_type, expected_revision)
}

/// Attach one verified program to one online cgroup/type direct list.
/// # C: O(descendants * effective programs)
pub fn attach(
    cgid: u64,
    attach_type: CgroupBpfAttachType,
    prog: InodeRef,
    mode: BpfAttachMode,
    order: BpfAttachOrder<'_>,
    replace: Option<&InodeRef>,
    expected_revision: u64,
) -> Result<(), BpfAttachError> {
    TREE.lock().bpf_attach(
        cgid, attach_type, prog, mode, order, replace, expected_revision,
    )
}

/// Attach one fd-backed link identity to one online cgroup/type direct list.
/// # C: O(descendants * effective programs)
pub fn attach_link(
    cgid: u64,
    attach_type: CgroupBpfAttachType,
    link_id: u64,
    prog: InodeRef,
    order: BpfAttachOrder<'_>,
    expected_revision: u64,
) -> Result<(), BpfAttachError> {
    TREE.lock().bpf_attach_link(
        cgid, attach_type, link_id, prog, order, expected_revision,
    )
}

/// Detach one exact program from one online cgroup/type direct list.
/// # C: O(descendants * effective programs)
pub fn detach(
    cgid: u64,
    attach_type: CgroupBpfAttachType,
    prog: Option<&InodeRef>,
    expected_revision: u64,
) -> Result<(), BpfAttachError> {
    TREE.lock().bpf_detach(cgid, attach_type, prog, expected_revision)
}

/// Detach one exact fd-backed link identity. # C: O(descendants * effective programs)
pub fn detach_link(
    cgid: u64,
    attach_type: CgroupBpfAttachType,
    link_id: u64,
) -> Result<(), BpfAttachError> {
    TREE.lock().bpf_detach_link(cgid, attach_type, link_id)
}

/// Swap the program one attached link runs, in place.
/// # C: O(descendants * effective programs)
pub fn replace_link(
    cgid: u64,
    attach_type: CgroupBpfAttachType,
    link_id: u64,
    prog: InodeRef,
    expect: Option<&InodeRef>,
) -> Result<(), BpfAttachError> {
    TREE.lock().bpf_replace_link(cgid, attach_type, link_id, prog, expect)
}

/// Snapshot one online cgroup/type effective array. # C: O(log nodes)
pub fn effective(
    cgid: u64,
    attach_type: CgroupBpfAttachType,
) -> Option<Arc<[InodeRef]>> {
    TREE.lock().bpf_effective(cgid, attach_type)
}

/// Snapshot direct metadata and one effective array. # C: O(direct)
pub fn query(
    cgid: u64,
    attach_type: CgroupBpfAttachType,
) -> Result<BpfAttachQuery, BpfAttachError> {
    TREE.lock().bpf_query(cgid, attach_type)
}

/// Pin one online cgroup's live effective-state owner. # C: O(log nodes)
pub fn runtime_for_cgid(cgid: u64) -> Result<Arc<CgroupBpfRuntime>, BpfAttachError> {
    TREE.lock().bpf_runtime(cgid)
}

/// Pin task membership and runtime under one hierarchy lock, falling back to ROOT.
/// # C: O(log nodes)
pub fn runtime_for_task(tid: u64) -> Arc<CgroupBpfRuntime> {
    TREE.lock().bpf_runtime_for_task(tid)
}

/// Pin the canonical ROOT runtime for hosted or no-current construction.
/// # C: O(log nodes)
pub fn root_runtime() -> Arc<CgroupBpfRuntime> {
    TREE.lock().bpf_root_runtime()
}

/// Compatibility target resolution for `BPF_CGROUP_DEVICE`. # C: O(log nodes)
pub fn device_target(cgid: u64) -> Result<DeviceTarget, BpfDeviceError> { target(cgid) }

/// Compatibility attach for append-only device programs.
/// # C: O(descendants * effective programs)
pub fn device_attach(
    cgid: u64,
    prog: InodeRef,
    mode: BpfDeviceMode,
    replace: Option<&InodeRef>,
    expected_revision: u64,
) -> Result<(), BpfDeviceError> {
    attach(
        cgid, CgroupBpfAttachType::Device, prog, mode,
        BpfAttachOrder::DEFAULT, replace, expected_revision,
    )
}

/// Compatibility device-program detach. # C: O(descendants * effective programs)
pub fn device_detach(
    cgid: u64,
    prog: Option<&InodeRef>,
    expected_revision: u64,
) -> Result<(), BpfDeviceError> {
    detach(cgid, CgroupBpfAttachType::Device, prog, expected_revision)
}

/// Compatibility device-program effective snapshot. # C: O(log nodes)
pub fn device_effective(cgid: u64) -> Option<Arc<[InodeRef]>> {
    effective(cgid, CgroupBpfAttachType::Device)
}

/// Compatibility task device-program effective snapshot. # C: O(log nodes)
pub fn device_effective_for_task(tid: u64) -> Option<Arc<[InodeRef]>> {
    Some(runtime_for_task(tid).effective(CgroupBpfAttachType::Device))
}

/// Compatibility device-program query. # C: O(direct)
pub fn device_query(cgid: u64) -> Result<BpfDeviceQuery, BpfDeviceError> {
    query(cgid, CgroupBpfAttachType::Device)
}
