// Per-task hardware breakpoint / watchpoint registers per `20§7` — the
// aarch64 counterpart of hal-x86_64's `debugreg`.
//
// Module manifest:
//   idreg  — ID_AA64DFR0_EL1 decode, the boot slot-count cache, `dbg_info`
//   ctrl   — DBGBCR/DBGWCR field contract + the slot validation ladder (pure)
//   layout — byte layout of the hardware-debug regset buffer (pure)
//   state  — `HwBreakpointState`, the plain per-task value a task embeds
//   exc    — debug-exception classifier → slot + SIGTRAP si_code (pure)
//   hw     — privileged DBGxVR/DBGxCR + MDSCR access, context switch (kernel)
//   tests  — hosted coverage of every pure layer
//
// Every layer except `hw` is ungated so `cargo test -p hal-aarch64` reaches it.

pub mod ctrl;
pub mod exc;
pub mod idreg;
pub mod layout;
pub mod state;

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub mod hw;

pub use ctrl::{
    bas_fields, bas_for_len, bas_len_bytes, decode, encode, parse, Ctrl, HwBpError, Installed,
    RegFile,
};
pub use exc::{classify, esr_ec, is_debug_ec, DebugEvent};
pub use idreg::{
    brps, dbg_info, debug_ver, init_from_id, num_brps, num_wrps, wrps, ARM_MAX_BRP, ARM_MAX_WRP,
};
pub use state::{DbgSlot, HwBreakpointState};

#[cfg(test)]
mod tests;
