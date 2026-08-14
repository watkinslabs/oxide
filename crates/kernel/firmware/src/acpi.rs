// Module manifest:
// - `log`: debug-gated ACPI logging helpers.
// - `read`: volatile little-endian reads from ACPI tables.
// - `rsdp`: RSDP parse flow, XSDT/RSDT walk, public entrypoints.
// - `tables`: per-table decoders and published ACPI-discovered state.
// - `fadt`: FADT decode and the reset-register admission ladder.
// - `iommu`: checksum-validated DMAR/IVRS inventory and boot publication.
// - `aml_handler`: canonical fallible OperationRegion backend boundary.
// - `aml_routes`: retained AML tables and PCI INTx route evaluation.
// - `pci_osc`: PCI root capability and ownership negotiation.

pub use aml::{AmlError, RegionAccess, RegionAccessDirection, value::RegionSpace};

mod log;
pub mod fadt;
mod iommu;
mod aml_handler;
mod aml_routes;
mod pci_osc;
#[cfg(target_os = "oxide-kernel")]
mod iort;
mod read;
mod rsdp;
mod tables;

pub use fadt::{Fadt, Gas, ResetAction, decode_fadt, parse_fadt, reset_action};
pub use aml_handler::{RegionBackend, install_region_backend};
pub use iommu::{AmdIvhdAlias, AmdIvhdScope, AmdIvhdSpecial, AmdIvmd, AMD_SPECIAL_HPET, AMD_SPECIAL_IOAPIC, DMAR_RMRR_SCOPE_UNIT, DmarRmrr, DmarScope, IommuError, IommuKind, IommuUnit, MAX_DMAR_PATH_BYTES, MAX_DMAR_RMRR_SCOPES, amd_ivmd, amd_ivmd_count, amd_vi_alias, amd_vi_alias_count, amd_vi_alias_for_requester, amd_vi_special, amd_vi_special_count, amd_vi_unit_for_requester, decode_dmar, decode_ivrs, dmar_rmrr, dmar_rmrr_count, dmar_scope, dmar_scope_count, dmar_x2apic_opt_out, iommu_unit, iommu_unit_count, iommu_unit_for_segment, parse_dmar, parse_ivrs};
pub use aml_routes::{PciIntxRoute, install_dsdt, install_ssdt, pci_intx_route, pci_osc_control, prepare_pci_intx_routes};
pub use pci_osc::PciOscControl;
pub use rsdp::{RsdpStatus, try_log_acpi, try_log_rsdp, try_log_xsdt};
pub use tables::{ECAM_BASE_PA, ECAM_BUS_END, ECAM_BUS_START, ECAM_SEGMENT, EcamWindow, GIC_MSI_FRAME_PA, GIC_ITS_PA, decode_gtdt, decode_hpet, decode_madt, decode_mcfg, decode_spcr, ecam_bus_cap, ecam_window, ecam_window_count};
pub use pci::MAX_ECAM_WINDOWS;
#[cfg(target_os = "oxide-kernel")]
pub use iort::{decode_iort, iort_msi_device_id};

#[cfg(test)]
mod tests;
