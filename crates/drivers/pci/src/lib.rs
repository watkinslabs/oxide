#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(any(test, feature = "hosted"))]
extern crate std;

extern crate alloc;

mod bars;
mod caps;
mod config_space;
mod scan;
mod layout;
mod types;
pub mod uapi;

pub use config_space::{
    interrupt_line, read8, read16, read_bytes, span, subsystem_ids, visible_size, write_bytes,
};

pub use bars::{
    bar_offset, decode_bars, probe_bar_resources, Bar, Resource, IORESOURCE_IO, IORESOURCE_MEM,
    IORESOURCE_PREFETCH,
};
pub use caps::{
    capabilities, decode_msi_cap, decode_msix_cap, disable_msi, emit_msix_teardown_steps,
    heapless_caps, msi_single_control_value, msix_control_enable_masked, msix_control_value,
    msix_table_entry_offset, program_msi_single, MsiCap, MsixCap, MsixTeardownStep, PciCap,
    CAP_ID_MSI, CAP_ID_MSIX, CAP_ID_PCIE, CAP_ID_VENDOR, MSI_ENABLE, MSIX_ENABLE,
    MSIX_FUNCTION_MASK, MSIX_MESSAGE_ADDR_HIGH_OFF, MSIX_MESSAGE_ADDR_LOW_OFF,
    MSIX_MESSAGE_DATA_OFF, MSIX_TABLE_ENTRY_BYTES, MSIX_VECTOR_CONTROL_MASKED,
    MSIX_VECTOR_CONTROL_OFF,
};
pub use scan::{enumerate, enumerate_buses};
pub use types::{
    disable_mem_bus_master, enable_mem_bus_master, intx_command_value, parse_bdf_addr,
    read_command, restore_intx_disabled, restore_mem_bus_master, set_intx_disabled,
    write_command, Bdf, ConfigSpaceReader, Error, KResult, PciDevice, COMMAND_BUS_MASTER,
    COMMAND_INTX_DISABLE, COMMAND_IO, COMMAND_MEMORY,
};

#[cfg(test)]
mod tests;
