// Local APIC bring-up and IRQ delivery.
//
// This is intentionally a manifest. LAPIC register/MSR state, IRQ dispatch,
// AP-startup IPI programming, timer programming, and boot enable paths live in
// separate modules so hardware responsibilities stay readable.

mod bringup;
mod dispatch;
mod ipi;
pub(crate) mod regs;
mod timer;

pub use bringup::{
    enable, enable_for_ap, enable_x2apic, install_diag_hooks, send_nmi_ipi, send_resched_ipi, LapicStatus,
};
pub use dispatch::{IRQ_LAST_VEC, IRQ_SEQ, RESCHED_IPI_COUNT, TICK_COUNT};
pub use crate::lapic_encoding::{build_icr_lo, icr_lo_init_assert, icr_lo_init_deassert,
    icr_lo_sipi};
pub use ipi::{wait_icr_idle, wait_icr_idle_timeout, write_icr};
pub use regs::{busy_wait_us, eoi, local_apic_id, LAPIC_BASE_VA};
pub use crate::lapic_shutdown::apply::{restore_boot_irq_mode, shutdown};
pub use timer::{timer_deadline_mode, timer_disarm, timer_periodic, timer_smoke};
