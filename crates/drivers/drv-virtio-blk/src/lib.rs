//! virtio-blk driver per `34§*` / `17§2`. The boot-time PCI probe in
//! `pci_boot::virtio_drv` negotiates VIRTIO_F_VERSION_1, programs
//! queue 0, and reaches DRIVER_OK; it then hands the persistent ring
//! addresses + device-cfg here via `modern::init_blk`, which builds a
//! `BlkState` request engine and registers a `BlockDevice` so ext4 can
//! mount a real disk.
//!
//! `modern` is the live request engine (HHDM ring access + MMIO
//! notify) — kernel-only. The request-chain *encoding* lives in the
//! `virtio::blk` crate and is host-tested below against a fake
//! in-memory ring (the verify-left gate, no boot).

#![no_std]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

#[cfg(target_os = "oxide-kernel")]
pub mod modern;

#[cfg(test)]
mod tests;
