//! virtio-blk driver per `34§*` / `17§2`. The model driver's `probe`
//! in the transport backend executes modern transport negotiation using
//! this driver's wanted feature policy, programs queue 0, reaches DRIVER_OK,
//! and hands the persistent ring addresses + device-cfg here via
//! `modern::init_blk`, which builds a `BlkState` request engine and registers
//! a `BlockDevice` so ext4 can mount a real disk.
//!
//! `modern` is the live request engine (HHDM ring access + MMIO
//! notify) — kernel-only. The request-chain *encoding* lives in the
//! `virtio::blk` crate and is host-tested below against a fake
//! in-memory ring (the verify-left gate, no boot).

#![no_std]

// dead_code is meaningful for this crate ONLY on the kernel target. A large
// part of it sits behind `cfg(target_os = "oxide-kernel")`, so a host build
// (`cargo test`, `cargo check --workspace`) compiles a strict subset and calls
// hundreds of live items dead. The kernel builds keep dead_code fully enabled
// and are warning-clean, and every one of these crates links into `kmain`, so
// nothing is hidden: real dead code still surfaces on `xtask kernel`.
#![cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]
extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

#[cfg(any(target_os = "oxide-kernel", test))]
pub mod modern;

#[cfg(test)]
mod tests;
