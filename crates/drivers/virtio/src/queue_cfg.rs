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

const QUEUE_ZERO: u16 = 0;
/// `program_queue` backs each split-virtqueue area with exactly ONE frame from
/// `VirtioQueueAllocator::alloc_frame`, so every area must fit in one frame.
const QUEUE_FRAME_BYTES: u64 = 4096;
/// `struct vring_desc` is addr/len/flags/next = 16 bytes (Virtio 1.2 §2.7.5).
const VRING_DESC_BYTES: u64 = 16;
/// Descriptor table is the binding area at 16 B/entry; at this N the avail ring
/// (6 + 2N bytes) and used ring (6 + 8N bytes) both still fit one frame.
const MAX_QUEUE_SIZE: u16 = (QUEUE_FRAME_BYTES / VRING_DESC_BYTES) as u16;
const QUEUE_ENABLE_READY: u16 = 1;
const QUEUE_ADDR_HIGH_OFF: u64 = 4;
const QUEUE_ADDR_LOW_MASK: u64 = 0xFFFF_FFFF;
const QUEUE_ADDR_HIGH_SHIFT: u32 = 32;

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
    let q0 = program_queue(cfg_va, QUEUE_ZERO, q0_msix_vec, allocator)?;
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
    let mut size = r16(CFG_QUEUE_SIZE);
    if size == 0 {
        return None;
    }
    // `size` is DEVICE-supplied. Every ring area below gets exactly one frame,
    // so a device advertising more entries than one frame holds would have the
    // driver's own descriptor/avail/used stores run off the end of that frame
    // (QEMU takes `queue-size=1024` on virtio-blk). Virtio 1.2 §4.1.4.3 makes
    // queue_size driver-writable down to a smaller power of two: negotiate it
    // down, then re-read, and refuse the queue if the device did not accept.
    if size > MAX_QUEUE_SIZE {
        w16(CFG_QUEUE_SIZE, MAX_QUEUE_SIZE);
        size = r16(CFG_QUEUE_SIZE);
        if size == 0 || size > MAX_QUEUE_SIZE {
            return None;
        }
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
    let _ = r16(CFG_QUEUE_MSIX);
    w32(CFG_QUEUE_DESC, queue_addr_low(desc_pa));
    w32(CFG_QUEUE_DESC + QUEUE_ADDR_HIGH_OFF, queue_addr_high(desc_pa));
    w32(CFG_QUEUE_DRIVER, queue_addr_low(driver_pa));
    w32(CFG_QUEUE_DRIVER + QUEUE_ADDR_HIGH_OFF, queue_addr_high(driver_pa));
    w32(CFG_QUEUE_DEVICE, queue_addr_low(device_pa));
    w32(CFG_QUEUE_DEVICE + QUEUE_ADDR_HIGH_OFF, queue_addr_high(device_pa));
    w16(CFG_QUEUE_ENABLE, QUEUE_ENABLE_READY);
    let _ = r16(CFG_QUEUE_ENABLE);
    w16(CFG_QUEUE_SELECT, QUEUE_ZERO);

    Some(QueueRing {
        desc_pa,
        driver_pa,
        device_pa,
        notify_off,
        size,
    })
}

const fn queue_addr_low(pa: u64) -> u32 {
    (pa & QUEUE_ADDR_LOW_MASK) as u32
}

const fn queue_addr_high(pa: u64) -> u32 {
    (pa >> QUEUE_ADDR_HIGH_SHIFT) as u32
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
        // SAFETY: base points at this test's own `[u64; 8]` fake common-cfg
        // register block, and CFG_QUEUE_SIZE (0x18) is an aligned u16 field
        // inside its 64 bytes, so the store is in bounds and aligned.
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
    fn program_queue_set_writes_q0_msix_vector() {
        const TEST_Q0_MSIX_VECTOR: u16 = 3;
        let mut cfg = [0u64; 8];
        let base = cfg.as_mut_ptr() as u64;
        // SAFETY: base points at this test's fake common-cfg register block
        // and CFG_QUEUE_SIZE is the aligned u16 queue-size field.
        unsafe {
            core::ptr::write_volatile((base + CFG_QUEUE_SIZE) as *mut u16, 128);
        }
        let mut allocator = TestAllocator::new(3);

        let queues = program_queue_set(base, &mut allocator, TEST_Q0_MSIX_VECTOR, &[None]);
        // SAFETY: base points at this test's fake common-cfg register block
        // and CFG_QUEUE_MSIX is the aligned u16 queue MSI-X field.
        let programmed_msix = unsafe {
            core::ptr::read_volatile((base + CFG_QUEUE_MSIX) as *const u16)
        };
        // SAFETY: base points at this test's fake common-cfg register block
        // and CFG_QUEUE_SELECT is the aligned u16 queue-select field.
        let selected_queue = unsafe {
            core::ptr::read_volatile((base + CFG_QUEUE_SELECT) as *const u16)
        };

        assert!(queues.is_some());
        assert_eq!(programmed_msix, TEST_Q0_MSIX_VECTOR);
        assert_eq!(selected_queue, QUEUE_ZERO);
    }

    #[test]
    fn program_queue_set_writes_extra_queue_msix_vector_by_plan_index() {
        const TEST_Q0_MSIX_VECTOR: u16 = 3;
        const TEST_EXTRA_QUEUE_INDEX: u16 = 3;
        const TEST_UNPLANNED_QUEUE_INDEX: u16 = 1;
        const TEST_EXTRA_MSIX_VECTOR: u16 = 7;
        const TEST_QUEUE_SIZE: u16 = 128;
        const TEST_COMMON_CFG_WORDS: usize = 8;
        const TEST_PROGRAMMED_QUEUE_FRAMES: usize = 6;
        let mut cfg = [0u64; TEST_COMMON_CFG_WORDS];
        let base = cfg.as_mut_ptr() as u64;
        // SAFETY: base points at this test's fake common-cfg register block
        // and CFG_QUEUE_SIZE is the aligned u16 queue-size field.
        unsafe {
            core::ptr::write_volatile((base + CFG_QUEUE_SIZE) as *mut u16, TEST_QUEUE_SIZE);
        }
        let mut extra_plans = [None; MAX_RESOURCE_QUEUES];
        extra_plans[TEST_EXTRA_QUEUE_INDEX as usize] =
            Some(VirtioQueuePlan::new(TEST_EXTRA_QUEUE_INDEX, None, true)
                .with_msix_vec(TEST_EXTRA_MSIX_VECTOR));
        let mut allocator = TestAllocator::new(TEST_PROGRAMMED_QUEUE_FRAMES);

        let queues = program_queue_set(base, &mut allocator, TEST_Q0_MSIX_VECTOR, &extra_plans)
            .expect("q0 and planned extra queue should program");
        // SAFETY: base points at this test's fake common-cfg register block
        // and CFG_QUEUE_MSIX is the aligned u16 queue MSI-X field.
        let programmed_msix = unsafe {
            core::ptr::read_volatile((base + CFG_QUEUE_MSIX) as *const u16)
        };
        // SAFETY: base points at this test's fake common-cfg register block
        // and CFG_QUEUE_SELECT is the aligned u16 queue-select field.
        let selected_queue = unsafe {
            core::ptr::read_volatile((base + CFG_QUEUE_SELECT) as *const u16)
        };

        assert!(queues.extra_queue(TEST_EXTRA_QUEUE_INDEX).is_some());
        assert!(queues.extra_queue(TEST_UNPLANNED_QUEUE_INDEX).is_none());
        assert_eq!(programmed_msix, TEST_EXTRA_MSIX_VECTOR);
        assert_eq!(selected_queue, QUEUE_ZERO);
    }

    /// A device may advertise more descriptors than the one frame per ring area
    /// that `program_queue` allocates. Without the §4.1.4.3 renegotiation the
    /// returned `size` licenses driver stores past the end of that frame.
    #[test]
    fn oversized_device_queue_size_is_negotiated_down_to_one_frame() {
        const DEVICE_ADVERTISED_QUEUE_SIZE: u16 = 1024;
        let mut cfg = [0u64; 8];
        let base = cfg.as_mut_ptr() as u64;
        // SAFETY: base points at this test's own `[u64; 8]` fake common-cfg
        // register block, and CFG_QUEUE_SIZE (0x18) is an aligned u16 field
        // inside its 64 bytes, so the store is in bounds and aligned.
        unsafe {
            core::ptr::write_volatile(
                (base + CFG_QUEUE_SIZE) as *mut u16, DEVICE_ADVERTISED_QUEUE_SIZE);
        }
        let mut allocator = TestAllocator::new(3);

        let ring = program_queue(base, 0, 0, &mut allocator)
            .expect("clamped queue should still program");

        assert_eq!(ring.size, MAX_QUEUE_SIZE);
        // SAFETY: base points at this test's own `[u64; 8]` fake common-cfg
        // register block, and CFG_QUEUE_SIZE (0x18) is an aligned u16 field
        // inside its 64 bytes, so the load is in bounds and aligned.
        let negotiated = unsafe {
            core::ptr::read_volatile((base + CFG_QUEUE_SIZE) as *const u16)
        };
        assert_eq!(negotiated, MAX_QUEUE_SIZE);
        assert!(MAX_QUEUE_SIZE as u64 * VRING_DESC_BYTES <= QUEUE_FRAME_BYTES);
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
