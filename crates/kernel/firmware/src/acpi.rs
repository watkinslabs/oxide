// Module manifest:
// - `log`: debug-gated ACPI logging helpers.
// - `read`: volatile little-endian reads from ACPI tables.
// - `rsdp`: RSDP parse flow, XSDT/RSDT walk, public entrypoints.
// - `tables`: per-table decoders and published ACPI-discovered state.

mod log;
mod read;
mod rsdp;
mod tables;

pub use rsdp::{RsdpStatus, try_log_acpi, try_log_rsdp, try_log_xsdt};
pub use tables::{ECAM_BASE_PA, GIC_MSI_FRAME_PA, GIC_ITS_PA, decode_gtdt, decode_hpet, decode_madt, decode_mcfg, decode_spcr};
#[cfg(target_os = "oxide-kernel")]
pub use tables::decode_iort;

#[cfg(test)]
mod tests;
