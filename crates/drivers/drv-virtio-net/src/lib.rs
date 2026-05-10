//! virtio-net driver per `34§*`. Per-arch HAL + net + pci.
//! `legacy` covers the legacy transport (memory-mapped vring at
//! BAR0); `modern` covers the modern transport (capability-list
//! driven, PCI MSI-X interrupts).

#![no_std]

extern crate alloc;

#[cfg(target_os = "oxide-kernel")]
pub mod legacy;
#[cfg(target_os = "oxide-kernel")]
pub mod modern;
