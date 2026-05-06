// virtio (modern, MMIO + PCI) per Virtio 1.2. v1 implements the
// shared queue layout — split virtqueue (descriptor ring +
// available ring + used ring) — plus the per-device IDs every
// driver consumes (net=1, blk=2, console=3, …).
//
// The MMIO accessor + IRQ wiring lives in arch-specific HAL
// crates; this crate is pure data shapes + ring math.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(any(test, feature = "hosted"))]
extern crate std;

extern crate alloc;

pub mod queue;
pub use queue::{
    Desc, AvailRing, UsedElem, UsedRing, VirtQueue,
    VRING_DESC_F_NEXT, VRING_DESC_F_WRITE, VRING_DESC_F_INDIRECT,
};

/// Virtio device IDs per spec §5.1.
pub const VIRTIO_DEV_NET:     u16 = 1;
pub const VIRTIO_DEV_BLOCK:   u16 = 2;
pub const VIRTIO_DEV_CONSOLE: u16 = 3;
pub const VIRTIO_DEV_RNG:     u16 = 4;
pub const VIRTIO_DEV_SCSI:    u16 = 8;

/// Status register bits per spec §2.1.
pub const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
pub const VIRTIO_STATUS_DRIVER:      u8 = 2;
pub const VIRTIO_STATUS_DRIVER_OK:   u8 = 4;
pub const VIRTIO_STATUS_FEATURES_OK: u8 = 8;
pub const VIRTIO_STATUS_FAILED:      u8 = 0x80;

/// Common feature bits (high bits = device-specific).
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
pub const VIRTIO_F_RING_INDIRECT_DESC: u64 = 1 << 28;
pub const VIRTIO_F_RING_EVENT_IDX:     u64 = 1 << 29;
