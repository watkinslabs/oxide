//! Sandboxed eBPF interpreter.
//!
//! Module manifest:
//! - execute: instruction decoding, ALU/JMP semantics, and execution loop.
//! - memory: context, stack, packet, map, and kernel-object memory domains.
//! - kfunc: kernel-BTF function dispatch.
//! - loaded: canonical loaded-program runners and statistics ownership.
//! - tests: instruction and helper execution coverage.

mod execute;
mod kfunc;
mod loaded;
mod memory;

pub use execute::{run, run_socket_filter, run_with_helpers, run_with_helpers_and_state,
    Helper, HelperFn, HelperState, ReuseportSelection, NUM_REGS, STACK_BYTES, STEP_BUDGET};
pub use loaded::{run_program_mut_with_state, run_program_with_state};
pub(crate) use execute::{verify_alu, verify_jump};
pub(crate) use loaded::run_program_with_kernel_state;

#[cfg(test)]
#[path = "bpf_interp_tests.rs"]
mod tests;
