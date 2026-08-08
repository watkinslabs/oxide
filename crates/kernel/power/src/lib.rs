// Power + reset per `32`.
//
// Owns the reboot/halt/poweroff endpoints invoked by:
//   - sys_reboot(2) (crates/kernel/syscalls/src/169_reboot.rs)
//   - panic-halt path (kmain::halt_forever)
//   - QEMU smoke shutdown (kmain end-of-boot)
//
// Module manifest:
// - `uapi`:    reboot(2) magic + command constants.
// - `decide`:  pure reboot(2) / reboot_pid_ns decisions
//              (magic pair, command classification, pid-namespace mapping,
//              RESTART2 string truncation) — host-tested.
// - `cad`:     the `C_A_D` global and `ctrl_alt_del()`'s rule.
// - `machine`: driver shutdown + the per-arch irreversible transition.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

pub mod uapi;
pub mod decide;
pub mod cad;
pub mod machine;

pub use uapi::*;
pub use decide::{check_magic, classify_cmd, pid_ns_reboot, reboot_precheck, restart2_cmd_len,
    Error, KResult, NsRebootSignal, RebootAction, TerminalCmd};
pub use cad::{cad_action, cad_enabled, set_cad, CadAction};
pub use machine::{halt, init, power_off, restart, restart_with_command,
    set_driver_shutdown_hook, terminal};
