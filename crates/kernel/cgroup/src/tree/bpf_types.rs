use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{LockClass, Spinlock};
use vfs::InodeRef;

/// Linux `BPF_CGROUP_MAX_PROGS` direct-list ceiling.
pub const MAX_BPF_ATTACH_PROGS: usize = 64;

/// Linux cgroup-BPF attachment slots owned independently by each cgroup.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CgroupBpfAttachType {
    Device,
    InetIngress,
    InetEgress,
    Inet4Bind,
    Inet6Bind,
    Inet4Connect,
    Inet6Connect,
    UnixConnect,
}

impl CgroupBpfAttachType {
    pub const ALL: [Self; 8] = [
        Self::Device,
        Self::InetIngress,
        Self::InetEgress,
        Self::Inet4Bind,
        Self::Inet6Bind,
        Self::Inet4Connect,
        Self::Inet6Connect,
        Self::UnixConnect,
    ];

    pub(super) const COUNT: usize = Self::ALL.len();

    pub(super) const fn index(self) -> usize {
        match self {
            Self::Device => 0,
            Self::InetIngress => 1,
            Self::InetEgress => 2,
            Self::Inet4Bind => 3,
            Self::Inet6Bind => 4,
            Self::Inet4Connect => 5,
            Self::Inet6Connect => 6,
            Self::UnixConnect => 7,
        }
    }
}

/// One direct-list attachment mode. Modes never mix within one cgroup/type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BpfAttachMode {
    Single,
    Override,
    Multi,
}

/// Exact owner identity selected as an ordering anchor.
#[derive(Clone, Copy)]
pub enum BpfAttachAnchor<'a> {
    Legacy(&'a InodeRef),
    Link(u64),
}

/// Direct-list insertion point for a multi attachment.
#[derive(Clone, Copy)]
pub enum BpfAttachPosition<'a> {
    Empty,
    First,
    Last,
    Before(BpfAttachAnchor<'a>),
    After(BpfAttachAnchor<'a>),
}

/// Linux cgroup-BPF list ordering: direct placement plus hierarchy preorder.
#[derive(Clone, Copy)]
pub struct BpfAttachOrder<'a> {
    pub position: BpfAttachPosition<'a>,
    pub preorder: bool,
}

impl BpfAttachOrder<'static> {
    pub const DEFAULT: Self = Self { position: BpfAttachPosition::Last, preorder: false };
    pub const PREORDER: Self = Self { position: BpfAttachPosition::Last, preorder: true };
}

/// Errors from the cgroup-owned program attachment lists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BpfAttachError {
    Offline,
    Duplicate,
    Missing,
    Full,
    Stale,
    Denied,
    Invalid,
}

/// Direct-program metadata plus one immutable effective-array snapshot.
pub struct BpfAttachQuery {
    pub direct: Arc<[InodeRef]>,
    pub effective: Arc<[InodeRef]>,
    pub revision: u64,
    pub mode: Option<BpfAttachMode>,
}

/// B1553 source-compatible device attachment mode.
pub type BpfDeviceMode = BpfAttachMode;
/// B1553 source-compatible device attachment error.
pub type BpfDeviceError = BpfAttachError;
/// B1553 source-compatible device query.
pub type BpfDeviceQuery = BpfAttachQuery;

pub(super) enum BpfAttachOwner {
    Legacy(InodeRef),
    Link { id: u64, prog: InodeRef },
}

impl BpfAttachOwner {
    /// Effective program exposed by either owner class. # C: O(1)
    pub(super) fn prog(&self) -> &InodeRef {
        match self {
            Self::Legacy(prog) | Self::Link { prog, .. } => prog,
        }
    }

    /// Exact owner-class and identity match. # C: O(1)
    pub(super) fn matches_anchor(&self, anchor: BpfAttachAnchor<'_>) -> bool {
        match (self, anchor) {
            (Self::Legacy(prog), BpfAttachAnchor::Legacy(anchor)) => Arc::ptr_eq(prog, anchor),
            (Self::Link { id, .. }, BpfAttachAnchor::Link(anchor)) => *id == anchor,
            _ => false,
        }
    }
}

pub(super) struct BpfAttachEntry {
    pub(super) owner: BpfAttachOwner,
    pub(super) preorder: bool,
}

pub(super) struct BpfAttachState {
    pub(super) direct: Vec<BpfAttachEntry>,
    pub(super) revision: u64,
    pub(super) mode: Option<BpfAttachMode>,
}

impl BpfAttachState {
    fn new() -> Self {
        // kernel/cgroup/cgroup.c initializes every `cgrp->bpf.revisions[]` to 1.
        Self { direct: Vec::new(), revision: 1, mode: None }
    }
}

struct CgroupBpfRuntimeLock;
impl LockClass for CgroupBpfRuntimeLock {
    fn rank() -> u16 { 150 }
    fn name() -> &'static str { "CgroupBpfRuntimeLock" }
}

/// Socket-pinnable live effective state for one cgroup.
///
/// A node and every socket created in it share this handle. Removing the node
/// drops direct state but cannot invalidate the last effective arrays observed
/// by sockets that still retain the handle.
pub struct CgroupBpfRuntime {
    cgid: u64,
    effective: Spinlock<[Arc<[InodeRef]>; CgroupBpfAttachType::COUNT], CgroupBpfRuntimeLock>,
}

impl CgroupBpfRuntime {
    /// Allocate one empty runtime owner. # C: O(attach types)
    pub(super) fn new(cgid: u64) -> Self {
        Self {
            cgid,
            effective: Spinlock::new(core::array::from_fn(|_| Arc::from([]))),
        }
    }

    /// Canonical cgroup id captured by this handle. # C: O(1)
    pub fn cgid(&self) -> u64 { self.cgid }

    /// Atomically snapshot one immutable effective program array. # C: O(1)
    pub fn effective(&self, attach_type: CgroupBpfAttachType) -> Arc<[InodeRef]> {
        Arc::clone(&self.effective.lock()[attach_type.index()])
    }

    /// Atomically replace one effective program array. # C: O(1)
    pub(super) fn publish(
        &self,
        attach_type: CgroupBpfAttachType,
        effective: Arc<[InodeRef]>,
    ) {
        self.effective.lock()[attach_type.index()] = effective;
    }
}

pub(super) struct CgroupBpfState {
    pub(super) direct: [BpfAttachState; CgroupBpfAttachType::COUNT],
    pub(super) runtime: Arc<CgroupBpfRuntime>,
}

impl CgroupBpfState {
    /// Allocate one node's canonical direct and effective state. # C: O(attach types)
    pub(super) fn new(cgid: u64) -> Self {
        Self {
            direct: core::array::from_fn(|_| BpfAttachState::new()),
            runtime: Arc::new(CgroupBpfRuntime::new(cgid)),
        }
    }

    /// Borrow one canonical direct slot. # C: O(1)
    pub(super) fn state(&self, attach_type: CgroupBpfAttachType) -> &BpfAttachState {
        &self.direct[attach_type.index()]
    }

    /// Mutably borrow one canonical direct slot. # C: O(1)
    pub(super) fn state_mut(
        &mut self,
        attach_type: CgroupBpfAttachType,
    ) -> &mut BpfAttachState {
        &mut self.direct[attach_type.index()]
    }
}
