// Module manifest: `core` owns syscall entry/exit sequencing; `ptrace` owns
// PTRACE_SYSCALL stop handling; `route_*` own syscall-number routing by domain.
#![cfg(target_os = "oxide-kernel")]

mod core;
mod ptrace;
mod route_a;
mod route_b;
mod route_c;

pub use core::oxide_syscall_dispatch;
