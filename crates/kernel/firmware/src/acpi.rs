// Module manifest:
// - `log`: debug-gated ACPI logging helpers.
// - `read`: volatile little-endian reads from ACPI tables.
// - `rsdp`: RSDP parse flow, XSDT/RSDT walk, public entrypoints.
// - `tables`: per-table decoders and published ACPI-discovered state.
// - `fadt`: FADT decode and the reset-register admission ladder.
// - `iommu`: checksum-validated DMAR/IVRS inventory and boot publication.

mod log;
pub mod fadt;
mod iommu;
#[cfg(target_os = "oxide-kernel")]
mod iort;
mod read;
mod rsdp;
mod tables;

pub use fadt::{Fadt, Gas, ResetAction, decode_fadt, parse_fadt, reset_action};
pub use iommu::{IommuError, IommuKind, IommuUnit, decode_dmar, decode_ivrs, iommu_unit, iommu_unit_count, parse_dmar, parse_ivrs};
pub use rsdp::{RsdpStatus, try_log_acpi, try_log_rsdp, try_log_xsdt};
pub use tables::{ECAM_BASE_PA, ECAM_BUS_END, ECAM_BUS_START, ECAM_SEGMENT, GIC_MSI_FRAME_PA, GIC_ITS_PA, decode_gtdt, decode_hpet, decode_madt, decode_mcfg, decode_spcr, ecam_bus_cap};
#[cfg(target_os = "oxide-kernel")]
pub use iort::{decode_iort, iort_msi_device_id};

#[cfg(test)]
mod tests;
