// Module manifest: `core` owns syscall entry/exit sequencing; `ptrace` owns
// PTRACE_SYSCALL stop handling; `seccomp` executes the filter verdict
// `security::seccomp` decides; `restart` owns the arch frame rewrite that
// re-enters a signal-interrupted syscall; `route_*` own syscall-number routing
// by domain.
#![cfg(target_os = "oxide-kernel")]

mod core;
mod ptrace;
mod seccomp;
pub(crate) mod restart;
mod route_a;
mod route_b;
mod route_c;

pub use core::oxide_syscall_dispatch;
