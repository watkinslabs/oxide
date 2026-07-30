// Module manifest:
// - `controllers`: controller bitsets, file tables, parse/format helpers.
// - `types`: core cgroup tree state and typed memory ownership ledgers.
// - `hierarchy`: mount/lookup/create/remove and directory surface helpers.
// - `accounting`: proc/thread/memory/io/cpu accounting and freezer state.
// - `files`: cgroup control-file read/write handling.

mod accounting;
#[cfg(test)]
mod accounting_tests;
mod bpf_device;
mod controllers;
mod files;
mod hierarchy;
mod types;

pub use controllers::{
    ALL, CORE_FILES, CPU, CPUSET, FILE_SLOT_UNKNOWN, IO, MEMORY, NONROOT_FILES, PIDS,
    controller_files, file_slot,
};
pub use bpf_device::{BpfDeviceError, BpfDeviceQuery};
pub use types::{BpfDeviceMode, CpuGroup, KResult, MemoryCharge, MemoryEvent, MemoryEvents, MemoryKind, MemoryPressure, MemoryPressureResult, MemoryStats, Node, ROOT, Tree};
