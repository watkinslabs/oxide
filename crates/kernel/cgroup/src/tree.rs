// Module manifest:
// - `controllers`: controller bitsets, file tables, parse/format helpers.
// - `types`: core cgroup tree state and typed memory ownership ledgers.
// - `bpf_types`: attach-neutral cgroup-BPF state and pinned runtime handles.
// - `bpf_attach`: per-type direct mutation and effective-list publication.
// - `hierarchy`: mount/lookup/create/remove and directory surface helpers.
// - `accounting`: proc/thread/memory/io/cpu accounting and freezer state.
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
mod types;

pub use controllers::{
    ALL, CORE_FILES, CPU, CPUSET, IO, MEMORY, NONROOT_FILES, PIDS, controller_files,
};
pub use bpf_types::{
    BpfAttachAnchor, BpfAttachError, BpfAttachMode, BpfAttachOrder, BpfAttachPosition, BpfAttachQuery,
    BpfDeviceError, BpfDeviceMode, BpfDeviceQuery, CgroupBpfAttachType, CgroupBpfRuntime,
    MAX_BPF_ATTACH_PROGS,
};
pub use types::{CpuGroup, KResult, MemoryCharge, MemoryEvent, MemoryEvents, MemoryKind, MemoryPressure, MemoryPressureResult, MemoryStats, Node, ROOT, Tree};
