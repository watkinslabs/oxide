//! virtio-net driver per `34§*`. Per-arch HAL + net + pci.
//! Modern virtio-net transport: capability-list driven PCI setup,
//! MMIO notify regions, and MSI-X interrupts.

#![no_std]

extern crate alloc;

#[cfg(any(test, target_os = "oxide-kernel"))]
pub mod modern;
