// Module manifest:
// - `log`: debug-gated ACPI logging helpers.
// - `read`: volatile little-endian reads from ACPI tables.
// - `rsdp`: RSDP parse flow, XSDT/RSDT walk, public entrypoints.
// - `tables`: per-table decoders and published ACPI-discovered state.
// - `fadt`: FADT decode and the reset-register admission ladder.
// - `facs`: FACS decode and the firmware-waking-vector write plan.
// - `sleep_types`: `_Sx` SLP_TYP ownership and the PM1 status register.
// - `iommu`: checksum-validated DMAR/IVRS inventory and boot publication.
// - `aml_handler`: canonical fallible OperationRegion backend boundary.
// - `aml_routes`: retained AML tables and PCI INTx route evaluation.
// - `pci_osc`: PCI root capability and ownership negotiation.
// - `power_action`: FADT and AML-derived terminal S5 action.
// - `aml_eval`: namespace read side for the ACPI device drivers below.
// - `battery`: control-method battery, published to the power-supply class.
// - `ac`: AC adapter, published to the power-supply class.
// - `video`: display brightness, published to the backlight class.

pub use aml::{AmlError, RegionAccess, RegionAccessDirection, value::RegionSpace};

mod log;
pub mod fadt;
pub mod facs;
pub mod sleep_types;
mod iommu;
mod aml_handler;
mod aml_routes;
mod pci_osc;
mod power_action;
pub mod ac;
pub mod aml_eval;
pub mod battery;
pub mod video;
#[cfg(target_os = "oxide-kernel")]
mod iort;
mod read;
mod rsdp;
mod tables;

pub use fadt::{Fadt, Gas, PowerOffAction, PowerRegisters, ResetAction, SPACE_SYSTEM_IO, SPACE_SYSTEM_MEMORY, decode_fadt, parse_fadt, power_registers, poweroff_action as build_poweroff_action, reset_action};
pub use facs::{Facs, WakingVectorWrites, facs, facs_pa, parse_facs, waking_vector_writes};
pub use sleep_types::{SleepRegisters, SleepState, sleep_action, sleep_types, state_declared, wake_status_registers, PM1_WAKE_STATUS};
pub use aml_handler::{RegionBackend, install_region_backend};
pub use iommu::{AmdIvhdAlias, AmdIvhdScope, AmdIvhdSpecial, AmdIvmd, AMD_SPECIAL_HPET, AMD_SPECIAL_IOAPIC, DMAR_RMRR_SCOPE_UNIT, DmarRmrr, DmarScope, IommuError, IommuKind, IommuUnit, MAX_DMAR_PATH_BYTES, MAX_DMAR_RMRR_SCOPES, amd_ivmd, amd_ivmd_count, amd_vi_alias, amd_vi_alias_count, amd_vi_alias_for_requester, amd_vi_special, amd_vi_special_count, amd_vi_unit_for_requester, decode_dmar, decode_ivrs, dmar_rmrr, dmar_rmrr_count, dmar_scope, dmar_scope_count, dmar_x2apic_opt_out, iommu_unit, iommu_unit_count, iommu_unit_for_segment, parse_dmar, parse_ivrs};
pub use aml_routes::{PciIntxRoute, install_dsdt, install_ssdt, pci_intx_route, pci_osc_control, prepare_pci_intx_routes};
pub use pci_osc::{PciOscControl, OSC_PCIE_AER_CONTROL};
pub use devices::init_devices;
pub use power_action::poweroff_action;
pub(crate) use power_action::set_power_registers;
pub use rsdp::{RsdpStatus, try_log_acpi, try_log_rsdp, try_log_xsdt};
pub use tables::{ECAM_BASE_PA, ECAM_BUS_END, ECAM_BUS_START, ECAM_SEGMENT, EcamWindow, GIC_MSI_FRAME_PA, GIC_ITS_PA, decode_gtdt, decode_hpet, decode_madt, decode_mcfg, decode_spcr, ecam_bus_cap, ecam_window, ecam_window_count};
pub use pci::MAX_ECAM_WINDOWS;
#[cfg(target_os = "oxide-kernel")]
pub use iort::{decode_iort, iort_msi_device_id};

mod devices;

#[cfg(test)]
mod tests;
