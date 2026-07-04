//! Boot-PMM adapter for shared virtio common-cfg queue programming.
//!
//! The queue register protocol lives in `virtio::queue_cfg`; pci-boot only
//! supplies the current physical-frame allocator and HHDM zeroing policy.

pub(super) use virtio::{ProgrammedQueues, QueueRing};

struct BootQueueAllocator {
    hhdm: u64,
}

impl virtio::VirtioQueueAllocator for BootQueueAllocator {
    fn alloc_frame(&mut self) -> Option<u64> {
        pmm::setup::alloc_raw_frame()
    }

    fn free_frame(&mut self, pa: u64) {
        // SAFETY: `pa` was returned by PMM during this queue-allocation
        // attempt and has not been published to any live queue.
        unsafe {
            pmm::setup::free_one_frame(pa);
        }
    }

    fn zero_frame(&mut self, pa: u64) {
        if self.hhdm == 0 {
            return;
        }
        let va = self.hhdm.wrapping_add(pa) as *mut u64;
        // SAFETY: HHDM covers all RAM PMM hands out; we own this freshly
        // allocated frame; aligned u64 stores stay within the 4 KiB page.
        unsafe {
            for i in 0..(0x1000 / 8) {
                core::ptr::write_volatile(va.add(i), 0);
            }
        }
    }
}

/// Program mandatory queue 0 and every requested extra queue through the same
/// common-cfg queue protocol. Extra queue failures are non-fatal here, matching
/// the old staged probe behavior; child probes validate the queues they
/// require before publishing runtime state.
/// # SAFETY: caller mapped `cfg_va` as a Device-attr virtio common-cfg window.
/// # C: O(N_extra) queue programs
pub(super) fn program_queue_set(
    cfg_va: u64,
    hhdm: u64,
    q0_msix_vec: u16,
    extra_plans: &[Option<virtio::VirtioQueuePlan>],
) -> Option<ProgrammedQueues> {
    let mut allocator = BootQueueAllocator { hhdm };
    virtio::program_queue_set(cfg_va, &mut allocator, q0_msix_vec, extra_plans)
}
