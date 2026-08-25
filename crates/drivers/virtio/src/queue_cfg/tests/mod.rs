use super::*;

use alloc::vec::Vec;

struct TestAllocator {
    next: u64,
    dma_offset: u64,
    remaining: usize,
    allocated: Vec<u64>,
    freed: Vec<u64>,
    zeroed: Vec<u64>,
}

impl TestAllocator {
    fn new(remaining: usize) -> Self {
        Self {
            next: 0x1000,
            dma_offset: 0,
            remaining,
            allocated: Vec::new(),
            freed: Vec::new(),
            zeroed: Vec::new(),
        }
    }

    fn with_dma_offset(remaining: usize, dma_offset: u64) -> Self {
        let mut allocator = Self::new(remaining);
        allocator.dma_offset = dma_offset;
        allocator
    }
}

impl VirtioQueueAllocator for TestAllocator {
    fn alloc_frame(&mut self) -> Option<VirtioDmaFrame> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let pa = self.next;
        self.next += 0x1000;
        self.allocated.push(pa);
        Some(VirtioDmaFrame { pa, dma: pa + self.dma_offset })
    }

    fn free_frame(&mut self, frame: VirtioDmaFrame) {
        self.freed.push(frame.pa);
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
fn queue_vector_readback_must_match_the_requested_entry() {
    assert!(queue_msix_accepted(3, 3));
    assert!(!queue_msix_accepted(3, crate::VIRTIO_MSI_NO_VECTOR));
    assert!(!queue_msix_accepted(3, 4));
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
fn queue_registers_receive_dma_addresses_not_cpu_physical_addresses() {
    const TEST_DMA_OFFSET: u64 = 0x10_0000;
    let mut cfg = [0u64; 8];
    let base = cfg.as_mut_ptr() as u64;
    // SAFETY: this local fake common-cfg contains the aligned queue-size
    // field and is writable for the duration of this test.
    unsafe { core::ptr::write_volatile((base + CFG_QUEUE_SIZE) as *mut u16, 8); }
    let mut allocator = TestAllocator::with_dma_offset(3, TEST_DMA_OFFSET);

    let ring = program_queue(base, 0, 0, &mut allocator).expect("queue programmed");
    // SAFETY: `program_queue` wrote the aligned le64 register as two u32 words
    // in this test-owned fake common-cfg block; `cfg` is a live 64-byte local
    // still in scope, so CFG_QUEUE_DESC+8 is within it and correctly aligned.
    let desc_dma = unsafe {
        core::ptr::read_volatile((base + CFG_QUEUE_DESC) as *const u64)
    };

    assert_eq!(ring.desc_pa, 0x1000);
    assert_eq!(ring.desc_dma, 0x1000 + TEST_DMA_OFFSET);
    assert_eq!(desc_dma, ring.desc_dma);
    assert_ne!(desc_dma, ring.desc_pa);
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
    let size = MAX_QUEUE_SIZE as u64;
    assert!(size * VRING_DESC_BYTES <= QUEUE_FRAME_BYTES);
    assert!(6 + 2 * size <= QUEUE_FRAME_BYTES, "avail flags/index/ring fit one frame");
    assert!(6 + 8 * size <= QUEUE_FRAME_BYTES, "used flags/index/elements fit one frame");
}

#[test]
fn programmed_queues_are_indexed_by_virtqueue() {
    let ring = |index: u16| QueueRing {
        desc_pa: 0x1000 + index as u64,
        desc_dma: 0x1000 + index as u64,
        driver_pa: 0x2000 + index as u64,
        driver_dma: 0x2000 + index as u64,
        device_pa: 0x3000 + index as u64,
        device_dma: 0x3000 + index as u64,
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
