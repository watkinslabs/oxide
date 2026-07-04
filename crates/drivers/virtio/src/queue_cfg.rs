//! Modern virtio common-cfg virtqueue programming.
//!
//! The common queue register protocol is transport/core logic. Concrete
//! transports provide queue memory through `VirtioQueueAllocator`, because the
//! backing allocator and direct-map policy are platform-owned.

use crate::{VirtioQueuePlan, MAX_RESOURCE_QUEUES};

// common-cfg field offsets, Virtio 1.2 §4.1.4.3. u16-precise stores are
// required for queue_select / queue_msix_vector / queue_enable.
pub const CFG_QUEUE_SELECT: u64 = 0x16;
pub const CFG_QUEUE_SIZE: u64 = 0x18;
pub const CFG_QUEUE_MSIX: u64 = 0x1A;
pub const CFG_QUEUE_ENABLE: u64 = 0x1C;
pub const CFG_QUEUE_NOTIFY: u64 = 0x1E;
pub const CFG_QUEUE_DESC: u64 = 0x20;
pub const CFG_QUEUE_DRIVER: u64 = 0x28;
pub const CFG_QUEUE_DEVICE: u64 = 0x30;

/// Queue memory provider used by the shared common-cfg queue protocol.
pub trait VirtioQueueAllocator {
    /// Allocate one zeroable 4 KiB frame usable by the device for a split
    /// virtqueue ring page.
    fn alloc_frame(&mut self) -> Option<u64>;

    /// Release a frame allocated by `alloc_frame`.
    fn free_frame(&mut self, pa: u64);

    /// Zero a freshly allocated frame before the device can observe it.
    fn zero_frame(&mut self, pa: u64);
}

/// Programmed virtqueue: the three ring PAs handed to the device, the
/// per-queue `queue_notify_off`, and the negotiated `queue_size`.
#[derive(Clone, Copy)]
pub struct QueueRing {
    pub desc_pa: u64,
    pub driver_pa: u64,
    pub device_pa: u64,
    pub notify_off: u16,
    pub size: u16,
}

pub struct ProgrammedQueues {
    pub q0: QueueRing,
    extra: [Option<QueueRing>; MAX_RESOURCE_QUEUES],
}

impl ProgrammedQueues {
    #[cfg(test)]
    pub(crate) const fn from_test_parts(
        q0: QueueRing,
        extra: [Option<QueueRing>; MAX_RESOURCE_QUEUES],
    ) -> Self {
        Self { q0, extra }
    }

    /// Return a programmed queue by virtqueue index. Queue 0 is the mandatory
    /// transport queue; other indexes are planned extra queues.
    /// # C: O(1)
    pub const fn queue(&self, index: u16) -> Option<QueueRing> {
        if index == 0 {
            Some(self.q0)
        } else {
            self.extra_queue(index)
        }
    }

    /// Return a planned extra queue by index. Queue 0 is intentionally not
    /// exposed through this helper; callers use `q0` for the mandatory queue.
    /// # C: O(1)
    pub const fn extra_queue(&self, index: u16) -> Option<QueueRing> {
        let index = index as usize;
        if index < MAX_RESOURCE_QUEUES {
            self.extra[index]
        } else {
            None
        }
    }
}

/// Program mandatory queue 0 and every requested extra queue through the same
/// common-cfg queue protocol. Extra queue failures are non-fatal here; child
/// probes validate the queues they require before publishing runtime state.
/// # SAFETY: caller mapped `cfg_va` as a Device-attr virtio common-cfg window.
/// # C: O(N_extra) queue programs
pub fn program_queue_set<A: VirtioQueueAllocator>(
    cfg_va: u64,
    allocator: &mut A,
    q0_msix_vec: u16,
    extra_plans: &[Option<VirtioQueuePlan>],
) -> Option<ProgrammedQueues> {
    let q0 = program_queue(cfg_va, 0, q0_msix_vec, allocator)?;
    let mut extra = [None; MAX_RESOURCE_QUEUES];
    for plan in extra_plans.iter().copied().flatten() {
        let index = plan.index as usize;
        if index >= MAX_RESOURCE_QUEUES {
            continue;
        }
        extra[index] = program_queue(cfg_va, plan.index, plan.msix_vec, allocator);
    }
    Some(ProgrammedQueues { q0, extra })
}

/// Program virtqueue `qi` on the modern common-cfg window at `cfg_va`.
///
/// This selects the queue, reads its `queue_size`, allocates and zeroes three
/// ring frames, writes ring PAs, binds `msix_vec`, enables the queue, and
/// restores `queue_select` to 0.
/// # SAFETY: caller mapped `cfg_va` as a Device-attr virtio common-cfg window.
/// # C: O(1) - 3 frame allocs + a fixed number of MMIO stores
pub fn program_queue<A: VirtioQueueAllocator>(
    cfg_va: u64,
    qi: u16,
    msix_vec: u16,
    allocator: &mut A,
) -> Option<QueueRing> {
    let w16 = |off: u64, v: u16| {
        // SAFETY: cfg_va is the Device-attr-mapped common-cfg window; per
        // Virtio 1.2 §4.1.4.3 the field at `off` is u16-aligned within it.
        unsafe {
            core::ptr::write_volatile((cfg_va + off) as *mut u16, v);
        }
    };
    let w32 = |off: u64, v: u32| {
        // SAFETY: cfg_va common-cfg window; queue_desc/driver/device le64
        // fields are written as the two u32 halves at `off`/`off+4`.
        unsafe {
            core::ptr::write_volatile((cfg_va + off) as *mut u32, v);
        }
    };
    let r16 = |off: u64| -> u16 {
        // SAFETY: cfg_va common-cfg window; aligned u16 load of the selected
        // queue's field at `off`.
        unsafe { core::ptr::read_volatile((cfg_va + off) as *const u16) }
    };

    w16(CFG_QUEUE_SELECT, qi);
    let size = r16(CFG_QUEUE_SIZE);
    if size == 0 {
        return None;
    }

    let desc_pa = allocator.alloc_frame()?;
    let Some(driver_pa) = allocator.alloc_frame() else {
        allocator.free_frame(desc_pa);
        return None;
    };
    let Some(device_pa) = allocator.alloc_frame() else {
        allocator.free_frame(driver_pa);
        allocator.free_frame(desc_pa);
        return None;
    };

    allocator.zero_frame(desc_pa);
    allocator.zero_frame(driver_pa);
    allocator.zero_frame(device_pa);

    w16(CFG_QUEUE_SELECT, qi);
    let notify_off = r16(CFG_QUEUE_NOTIFY);
    w16(CFG_QUEUE_MSIX, msix_vec);
    w32(CFG_QUEUE_DESC, (desc_pa & 0xFFFF_FFFF) as u32);
    w32(CFG_QUEUE_DESC + 4, (desc_pa >> 32) as u32);
    w32(CFG_QUEUE_DRIVER, (driver_pa & 0xFFFF_FFFF) as u32);
    w32(CFG_QUEUE_DRIVER + 4, (driver_pa >> 32) as u32);
    w32(CFG_QUEUE_DEVICE, (device_pa & 0xFFFF_FFFF) as u32);
    w32(CFG_QUEUE_DEVICE + 4, (device_pa >> 32) as u32);
    w16(CFG_QUEUE_ENABLE, 1);
    w16(CFG_QUEUE_SELECT, 0);

    Some(QueueRing {
        desc_pa,
        driver_pa,
        device_pa,
        notify_off,
        size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    struct TestAllocator {
        next: u64,
        remaining: usize,
        allocated: Vec<u64>,
        freed: Vec<u64>,
        zeroed: Vec<u64>,
    }

    impl TestAllocator {
        fn new(remaining: usize) -> Self {
            Self {
                next: 0x1000,
                remaining,
                allocated: Vec::new(),
                freed: Vec::new(),
                zeroed: Vec::new(),
            }
        }
    }

    impl VirtioQueueAllocator for TestAllocator {
        fn alloc_frame(&mut self) -> Option<u64> {
            if self.remaining == 0 {
                return None;
            }
            self.remaining -= 1;
            let pa = self.next;
            self.next += 0x1000;
            self.allocated.push(pa);
            Some(pa)
        }

        fn free_frame(&mut self, pa: u64) {
            self.freed.push(pa);
        }

        fn zero_frame(&mut self, pa: u64) {
            self.zeroed.push(pa);
        }
    }

    #[test]
    fn absent_queue_does_not_allocate() {
        let mut cfg = [0u64; 8];
        let mut allocator = TestAllocator::new(3);

        let ring = program_queue(cfg.as_mut_ptr() as u64, 0, 0, &mut allocator);

        assert!(ring.is_none());
        assert!(allocator.allocated.is_empty());
        assert!(allocator.freed.is_empty());
        assert!(allocator.zeroed.is_empty());
    }

    #[test]
    fn partial_allocation_failure_unwinds_frames() {
        let mut cfg = [0u64; 8];
        let base = cfg.as_mut_ptr() as u64;
        unsafe {
            core::ptr::write_volatile((base + CFG_QUEUE_SIZE) as *mut u16, 128);
        }
        let mut allocator = TestAllocator::new(2);

        let ring = program_queue(base, 0, 0, &mut allocator);

        assert!(ring.is_none());
        assert_eq!(allocator.allocated, [0x1000, 0x2000]);
        assert_eq!(allocator.freed, [0x2000, 0x1000]);
        assert!(allocator.zeroed.is_empty());
    }

    #[test]
    fn programmed_queues_are_indexed_by_virtqueue() {
        let ring = |index: u16| QueueRing {
            desc_pa: 0x1000 + index as u64,
            driver_pa: 0x2000 + index as u64,
            device_pa: 0x3000 + index as u64,
            notify_off: index,
            size: 128,
        };
        let mut extra = [None; crate::MAX_RESOURCE_QUEUES];
        extra[1] = Some(ring(1));
        extra[3] = Some(ring(3));
        let queues = ProgrammedQueues { q0: ring(0), extra };

        assert_eq!(queues.queue(0).map(|queue| queue.notify_off), Some(0));
        assert_eq!(queues.queue(1).map(|queue| queue.notify_off), Some(1));
        assert_eq!(queues.queue(2).map(|queue| queue.notify_off), None);
        assert_eq!(queues.queue(3).map(|queue| queue.notify_off), Some(3));
        assert_eq!(queues.queue(4).map(|queue| queue.notify_off), None);
    }
}
