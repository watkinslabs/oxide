// Flattened Device Tree reader — the one FDT parser in the tree.
//
// The aarch64 boot stub reads `/memory`, `/chosen/bootargs`, `/cpus` and the
// PL011 clock out of the firmware blob before there is a heap; the kernel
// later re-reads the same retained blob to publish `/sys/firmware/fdt` and
// `/sys/firmware/devicetree/base`. Both consume this crate, so there is one
// decoder rather than a boot copy and a runtime copy that can disagree.
//
// Everything here is pure and target-independent: no allocator below the
// `alloc` feature, no logging, no I/O. That is what makes the parsing and the
// sysfs naming rules testable on a host against a fixture blob.
//
// FDT spec: https://devicetree-specification.readthedocs.io/en/v0.4/
// flattened-format.html — wire format is big-endian throughout.
//
// Module manifest:
//   build    — writing a blob, for a firmware that supplied none
//   header   — header decode/validation, token constants, `totalsize` probe
//   walk     — the single struct-block walker + `find_prop`
//   props    — the concrete boot-path properties read through `walk`
//   cpu      — `/cpus` hardware identities and availability
//   opp      — CPU OPP-table phandle-graph decoder
//   provider — fixed, fixed-factor, and regulator provider decoder
//   scmi     — SMC SCMI performance transport and CPU-domain decoder
//   idle     — per-CPU PSCI idle-state phandle-graph decoder
//   psci     — PSCI call-conduit decoder
//   uapi     — userspace ABI paths and modes for the published tree
//   of_tree  — blob → `/sys/firmware/devicetree` path/property entries (alloc)
//   fixture  — wire-image builder for tests (feature `fixture`)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

pub mod build;
pub mod header;
pub mod uapi;
pub mod props;
pub mod walk;
pub mod cpu;
pub mod opp;
pub mod provider;
pub mod scmi;
pub mod idle;
pub mod psci;

#[cfg(any(test, feature = "alloc"))]
pub mod of_tree;

// Wire-image builder. Off by default; the exporter's tests in `sysfs` turn it
// on so both sides test against the same fixtures rather than two hand-typed
// approximations of one blob.
#[cfg(any(test, feature = "fixture"))]
pub mod fixture;

pub use header::{
    parse_header, totalsize_from_prefix, DtbError, FdtHeader, KResult, FDT_HEADER_LEN,
    FDT_LAST_COMPAT_VERSION, FDT_MAGIC, FDT_MAX_TOTALSIZE, FDT_RSVMAP_ENTRY_LEN,
};
pub use props::{
    bootargs_via_prefix, chosen_bootargs, memory_regions, contains_string, enum_cpus, first_memory_region, machine_model, pl011_clock_hz, pl031_rtc, simple_framebuffer, Pl031Rtc, SimpleFramebuffer,
};
pub use cpu::{cpu_nodes, CpuNode};
pub use opp::{cpu_opp_tables, ClockReference, CpuOppTable, OppVoltage, OperatingPoint, RequiredOpp};
pub use provider::{fixed_providers, FixedClock, FixedFactorClock, FixedProviders, FixedRegulator};
pub use scmi::{scmi_perf_protocols, ScmiCompletionIrq, ScmiCpuDomain, ScmiPerfProtocol, ScmiSharedMemory, ScmiSmcTransport};
pub use idle::{cpu_idle_tables, CpuIdleState, CpuIdleTable};
pub use psci::{psci_conduit, PsciConduit};
pub use build::{uefi_stub_tree, Builder, EfiFirmware, UefiHandoff};
pub use uapi::{
    OF_PROC_NAME, OF_PROP_MODE, OF_RAW_MODE, OF_ROOT_DIR, OF_SECURE_PREFIX, OF_SECURE_PROP_MODE,
    OF_SYSFS_BASE, OF_SYSFS_KSET, OF_SYSFS_RAW,
};
pub use walk::{find_prop, walk, Event, Flow};

extern crate alloc;
#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
