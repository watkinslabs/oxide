use super::{alloc_net_tx_boot_buffer, post_net_rx_boot_buffer, program_queue_set};
use super::{read_queue_used_idx, NetRxBootBuffer, ProgrammedQueues, QueueRing};

#[derive(Clone, Copy)]
pub(super) struct VirtioPciRuntime {
    pub(super) hhdm: u64,
}

impl VirtioPciRuntime {
    pub(super) fn current() -> Self {
        Self {
            hhdm: {
                #[cfg(target_arch = "x86_64")]
                {
                    hal_x86_64::mmu_ops::hhdm_offset()
                }
                #[cfg(target_arch = "aarch64")]
                {
                    hal_aarch64::mmu_ops::hhdm_offset()
                }
            },
        }
    }

    pub(super) fn program_queue_set(
        self,
        cfg_va: u64,
        q0_msix_vec: u16,
        queue_plans: &[Option<virtio::VirtioQueuePlan>],
    ) -> Option<ProgrammedQueues> {
        program_queue_set(cfg_va, self.hhdm, q0_msix_vec, queue_plans)
    }

    pub(super) fn post_net_rx_boot_buffer(self, q0_ring: Option<QueueRing>) -> NetRxBootBuffer {
        post_net_rx_boot_buffer(self.hhdm, q0_ring)
    }

    pub(super) fn alloc_net_tx_boot_buffer(self, q1_ring: Option<QueueRing>, q1_notify_va: u64) -> u64 {
        alloc_net_tx_boot_buffer(self.hhdm, q1_ring, q1_notify_va)
    }

    pub(super) fn read_queue_used_idx(self, q0_ring: Option<QueueRing>) -> u16 {
        read_queue_used_idx(self.hhdm, q0_ring)
    }
}
