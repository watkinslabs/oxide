// AArch64 exception-vector assembly is divided by entry ownership:
// the table, synchronous fault entry, lower-EL syscall/fault entry, and IRQ
// entry/return each have an independent frame contract.

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
mod vector;
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
mod default;
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
mod lower_sync;
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
mod irq;

