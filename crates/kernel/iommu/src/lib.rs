#![no_std]
extern crate alloc;
// Module manifest: amd_vi owns AMD-Vi registers and activation; domain owns requester domains.
mod amd_vi;
mod amd_vi_bootstrap;
mod amd_vi_manager;
mod amd_vi_pt;
mod amd_vi_pt_tree;
mod domain;
mod vtd;
mod vtd_hw;
pub use amd_vi::{AmdViCommand, AmdViDte, AmdViRegisters, AmdViState, AmdViTables, AmdViUnit, COMMAND_BUFFER, COMMAND_HEAD, COMMAND_TAIL,
    CONTROL, CONTROL_COHERENT_ENABLE, CONTROL_COMMAND_ENABLE, CONTROL_COMPLETION_ENABLE, CONTROL_EVENT_ENABLE, CONTROL_IOMMU_ENABLE, DEVICE_TABLE, EVENT_HEAD, EVENT_LOG, EVENT_TAIL};
pub use amd_vi_bootstrap::AmdViBootstrap;
pub use amd_vi_manager::{AmdViActivation, activate_amd_vi};
pub use amd_vi_pt::{AmdViPte, iova_indices};
pub use amd_vi_pt_tree::AmdViPageTable;
pub use domain::{AmdViDomain, Domain, Mapping, amd_vi_unit_for_bdf};
pub use vtd::intel_vtd_unit_for_bdf;
pub use vtd_hw::{VtdContextEntry, VtdRegisters, VtdRootEntry};

#[cfg(test)] extern crate std;
