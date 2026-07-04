#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(any(test, feature = "hosted"))]
extern crate std;

extern crate alloc;

mod bars;
mod caps;
mod scan;
mod types;

pub use bars::{
    bar_offset, decode_bars, probe_bar_resources, Bar, Resource, IORESOURCE_IO, IORESOURCE_MEM,
    IORESOURCE_PREFETCH,
};
pub use caps::{
    capabilities, decode_msix_cap, heapless_caps, MsixCap, PciCap, CAP_ID_MSI, CAP_ID_MSIX,
    CAP_ID_PCIE, CAP_ID_VENDOR,
};
pub use scan::{enumerate, enumerate_buses};
pub use types::{
    disable_mem_bus_master, enable_mem_bus_master, parse_bdf_addr, read_command, write_command,
    Bdf, ConfigSpaceReader, Error, KResult, PciDevice, COMMAND_BUS_MASTER, COMMAND_IO,
    COMMAND_MEMORY,
};

#[cfg(test)]
mod tests;
