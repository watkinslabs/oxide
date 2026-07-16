// GICv3 bring-up and interrupt dispatch.
//
// This is a manifest. Distributor/redistributor register state, CPU-interface
// bring-up, SGI/IPI helpers, interrupt-line programming, LPI setup, and IRQ
// dispatch live in separate modules.

mod bringup;
mod dispatch;
mod ids;
mod lines;
mod lpi;
mod regs;
mod sgi;

pub use bringup::{ap_cpu_interface_enable, enable, gicr_base, GicStatus, GICR_STRIDE};
pub use dispatch::{LAST_INTID, TICK_COUNT, UART_IRQ_FIRES};
pub use lines::{disable_intid, enable_intid, enable_intid_level, ispendr_word};
pub use lpi::{lpi_set_config, lpis_enable, LpisStatus, LPI_BASE, LPI_PROP_DEFAULT};
pub use sgi::{enable_sgi_on, install_diag_hooks, send_resched_ipi, send_sgi, RESCHED_SGI};

#[cfg(test)]
mod tests;
