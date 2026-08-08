// Module manifest:
// - `controllers`: controller bitsets, file tables, parse/format helpers.
// - `types`: core cgroup tree state and typed memory ownership ledgers.
// - `bpf_types`: attach-neutral cgroup-BPF state and pinned runtime handles.
// - `bpf_attach`: per-type direct mutation and effective-list publication.
// - `hierarchy`: mount/lookup/create/remove and directory surface helpers.
// - `accounting`: proc/thread/memory/io/cpu accounting and freezer state.
// - `hugetlb_types`: huge-page granule identity, counter pair, file tables.
// - `hugetlb`: hugetlb charge/uncharge, limits, reparenting and its files.
// - `files`: cgroup control-file read/write handling.

mod accounting;
#[cfg(test)]
mod accounting_tests;
mod bpf_attach;
#[cfg(test)]
mod bpf_attach_tests;
mod bpf_types;
mod controllers;
mod files;
mod hierarchy;
mod hugetlb;
mod hugetlb_types;
#[cfg(test)]
mod hugetlb_tests;
mod types;

pub use controllers::{
    ALL, CORE_FILES, CPU, CPUSET, HUGETLB, IO, MEMORY, NONROOT_FILES, PIDS, controller_files,
};
pub use hugetlb::HugeChargeRefused;
pub use hugetlb_types::{
    HierarchyKind, HugeAttr, HugeCounter, HugeCounterKind, HugeEvents, HugeFile, HugeGranule,
    HugetlbState, HUGE_COUNTER_MAX_PAGES, HUGE_GRANULES,
};
pub use bpf_types::{
    BpfAttachAnchor, BpfAttachError, BpfAttachMode, BpfAttachOrder, BpfAttachPosition, BpfAttachQuery,
    BpfDeviceError, BpfDeviceMode, BpfDeviceQuery, CgroupBpfAttachType, CgroupBpfRuntime,
    MAX_BPF_ATTACH_PROGS,
};
pub use types::{CpuGroup, KResult, MemoryCharge, MemoryEvent, MemoryEvents, MemoryKind, MemoryPressure, MemoryPressureResult, MemoryStats, Node, ROOT, Tree};
