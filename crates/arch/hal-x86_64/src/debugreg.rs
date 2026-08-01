// Per-task hardware debug registers (DR0-DR3, DR6, DR7) per `20§7`.
//
// Module manifest:
//   dr7   — DR7 bit contract + the ptrace DR7/address validation ladder (pure)
//   dr6   — DR6 bit contract + #DB cause classifier → SIGTRAP si_code (pure)
//   state — `DebugRegs`, the plain per-task value a task struct embeds
//   hw    — privileged DR load/store + the context-switch fast path (kernel target)
//   tests — hosted coverage of the two pure layers
//
// Separate from the kernel-diagnostic watchpoint helpers in `regs.rs`, which
// arm DR0/DR1 for heap-corruption hunts; both name their DR7 fields from `dr7`.

pub mod dr6;
pub mod dr7;
mod state;

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub mod hw;

pub use dr6::Dr6Status;
pub use dr7::{validate_addr, validate_dr7, Dr7Error, HBP_NUM};
pub use state::DebugRegs;

#[cfg(test)]
mod tests;
