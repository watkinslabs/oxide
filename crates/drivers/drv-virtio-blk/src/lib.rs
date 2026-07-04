//! virtio-blk driver per `34§*` / `17§2`. The model driver's `probe`
//! in `pci_boot::virtio_drv` executes modern transport negotiation using
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

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

#[cfg(any(target_os = "oxide-kernel", test))]
pub mod modern;

#[cfg(test)]
mod tests;
