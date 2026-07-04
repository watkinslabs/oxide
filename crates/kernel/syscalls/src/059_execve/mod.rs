// Module manifest: `fd_table` owns exec-time fd-table unshare/close-on-exec;
// `x86_64` and `aarch64` own the arch-specific execve entry/activation paths.
#![cfg(target_os = "oxide-kernel")]

mod fd_table;
#[cfg(target_arch = "aarch64")] mod aarch64;
#[cfg(target_arch = "x86_64")] mod x86_64;

#[cfg(target_arch = "aarch64")] pub use aarch64::{execve_inner, sys_execve};
#[cfg(target_arch = "x86_64")] pub use x86_64::{execve_inner, sys_execve};
