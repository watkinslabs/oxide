#![no_std]
extern crate alloc;
// Module manifest: amd_vi owns AMD-Vi registers and activation; domain owns requester domains.
mod amd_vi;
mod domain;
pub use amd_vi::{AmdViRegisters, AmdViState, AmdViTables, AmdViUnit, COMMAND_BUFFER, COMMAND_HEAD, COMMAND_TAIL,
    CONTROL, CONTROL_COMMAND_ENABLE, CONTROL_EVENT_ENABLE, CONTROL_IOMMU_ENABLE, DEVICE_TABLE, EVENT_HEAD, EVENT_LOG, EVENT_TAIL};
pub use domain::{Domain, Mapping, amd_vi_unit_for_bdf};

#[cfg(test)] extern crate std;
