#![no_std]
extern crate alloc;
// Module manifest: amd_vi owns AMD-Vi registers and activation; domain owns requester domains.
mod amd_vi;
mod amd_vi_event;
mod amd_vi_ir;
mod admission;
mod dma_span;
mod dma_owner;
mod amd_vi_bootstrap;
mod amd_vi_manager;
mod amd_vi_pt;
mod amd_vi_pt_tree;
mod domain;
mod vtd;
mod vtd_hw;
mod vtd_pt;
mod vtd_pt_tree;
mod vtd_tables;
mod vtd_ir;
mod vtd_manager;
pub use amd_vi::{AmdViCommand, AmdViDte, AmdViRegisters, AmdViState, AmdViTables, AmdViUnit, COMMAND_BUFFER, COMMAND_HEAD, COMMAND_TAIL,
    CONTROL, CONTROL_COHERENT_ENABLE, CONTROL_COMMAND_ENABLE, CONTROL_COMPLETION_ENABLE, CONTROL_EVENT_ENABLE, CONTROL_IOMMU_ENABLE, DEVICE_TABLE, EVENT_HEAD, EVENT_LOG, EVENT_TAIL, EXT_FEATURES};
pub use amd_vi_event::{AmdViEvent, AmdViEventKind};
pub use amd_vi_ir::{AmdViIrMode, AmdViIrTable};
pub use admission::{admit_boot_requesters, bus_master_admitted};
pub use dma_owner::{map_dma, map_dma_below, unmap_dma};
pub use amd_vi_bootstrap::AmdViBootstrap;
pub use amd_vi_manager::{AmdViActivation, AmdViIoapic, AmdViMsi, activate_amd_vi, allocate_amd_vi_ioapic, allocate_amd_vi_msi, amd_vi_event_records, disable_amd_vi_event_interrupts, enable_amd_vi_event_interrupts, handle_amd_vi_event_interrupt, poll_amd_vi_events};
pub use amd_vi_pt::{AmdViPte, iova_indices};
pub use amd_vi_pt_tree::AmdViPageTable;
pub use domain::{AmdViDomain, Domain, Mapping, amd_vi_unit_for_bdf};
pub use vtd::{intel_vtd_hpet_source, intel_vtd_ioapic_source, intel_vtd_rmrr_count, intel_vtd_rmrr_for_bdf, intel_vtd_unit_for_bdf};
pub(crate) use vtd::vtd_dma_groups;
pub use vtd_hw::{VtdContextEntry, VtdQiDesc, VtdQiQueue, VtdRegisters, VtdRootEntry};
pub use vtd_pt::VtdPte;
pub use vtd_pt_tree::VtdPageTable;
pub use vtd_tables::VtdTables;
pub use vtd_ir::{VtdIrTable, VtdIrte, invalidate_irte, remapped_msi};
pub use vtd_manager::{VtdActivation, VtdHpet, VtdIoapic, VtdMsi, activate_vtd, allocate_vtd_hpet, allocate_vtd_ioapic, allocate_vtd_msi, enable_vtd_interrupt_remapping, vtd_eim_capable};

#[cfg(test)] extern crate std;
