//! Virtio-pci transport MMIO, queue-memory, and notify helpers.
//!
//! This module owns BAR-derived transport mappings used by virtio-pci probe
//! and runtime records, plus the boot PMM adapter for virtqueue frames. It
//! keeps transport resource lifetime separate from device-specific child probe
//! logic.

use alloc::vec::Vec;

mod msix;

pub(super) use msix::{
    MsixBinding, bind_msix_vector, disable_pci_command, publish_transport_record,
    release_failed_probe, release_msix_binding, release_msix_bindings, unpublish_transport_record,
};
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

#[derive(Clone, Copy, Default)]
pub(super) struct NetRxBootBuffer {
    pub(super) bufs: [virtio::VirtioNetRxBuffer; virtio::VIRTIO_NET_RX_BOOT_POOL],
    pub(super) bufs_len: usize,
    pub(super) avail_idx_posted: u16,
}

pub(super) fn post_net_rx_boot_buffer(hhdm: u64, q0: Option<QueueRing>) -> NetRxBootBuffer {
    const RX_BUF_LEN: u16 = 2048;
    let Some(q0) = q0 else {
        return NetRxBootBuffer::default();
    };
    if hhdm == 0 || q0.desc_pa == 0 || q0.driver_pa == 0 {
        return NetRxBootBuffer::default();
    }
    let pool_len = (q0.size as usize).min(virtio::VIRTIO_NET_RX_BOOT_POOL);
    if pool_len == 0 {
        return NetRxBootBuffer::default();
    }

    let mut bufs = [virtio::VirtioNetRxBuffer::default(); virtio::VIRTIO_NET_RX_BOOT_POOL];
    let mut bufs_len = 0usize;
    for desc_id in 0..pool_len {
        let Some(rx_pa) = pmm::setup::alloc_raw_frame() else {
            break;
        };
        let desc = (hhdm.wrapping_add(q0.desc_pa) + (desc_id as u64) * 16) as *mut u8;
        // SAFETY: HHDM maps the freshly allocated RX frame and queue-0
        // descriptor table. The transport owns these descriptors until the
        // child driver takes the resource handoff.
        unsafe {
            core::ptr::write_volatile(desc as *mut u64, rx_pa);
            core::ptr::write_volatile((desc.add(8)) as *mut u32, RX_BUF_LEN as u32);
            core::ptr::write_volatile((desc.add(12)) as *mut u16, virtio::VRING_DESC_F_WRITE);
            core::ptr::write_volatile((desc.add(14)) as *mut u16, 0u16);
        }
        bufs[bufs_len] = virtio::VirtioNetRxBuffer {
            desc_id: desc_id as u16,
            pa: rx_pa,
            len: RX_BUF_LEN,
        };
        bufs_len += 1;
    }
    if bufs_len == 0 {
        return NetRxBootBuffer::default();
    }

    let avail = (hhdm.wrapping_add(q0.driver_pa)) as *mut u16;
    for (slot, buf) in bufs.iter().take(bufs_len).enumerate() {
        // SAFETY: HHDM maps the queue-0 avail ring frame. ring[slot] starts at
        // u16 offset 2 and idx is u16 offset 1.
        unsafe {
            core::ptr::write_volatile(avail.add(2 + slot), buf.desc_id);
        }
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
    // SAFETY: same avail ring; idx publishes the descriptor pool after the
    // release fence made descriptor and ring writes observable.
    unsafe {
        core::ptr::write_volatile(avail.add(1), bufs_len as u16);
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);

    NetRxBootBuffer {
        bufs,
        bufs_len,
        avail_idx_posted: bufs_len as u16,
    }
}

pub(super) fn alloc_net_tx_boot_buffer(
    hhdm: u64,
    q1: Option<QueueRing>,
    q1_notify_va: u64,
) -> u64 {
    let Some(q1) = q1 else {
        return 0;
    };
    if hhdm == 0
        || q1.desc_pa == 0
        || q1.driver_pa == 0
        || q1.device_pa == 0
        || q1_notify_va == 0
    {
        return 0;
    }
    pmm::setup::alloc_raw_frame().unwrap_or(0)
}

pub(super) fn read_queue_used_idx(hhdm: u64, queue: Option<QueueRing>) -> u16 {
    let Some(queue) = queue else {
        return 0;
    };
    if hhdm == 0 || queue.device_pa == 0 {
        return 0;
    }
    let used = (hhdm.wrapping_add(queue.device_pa)) as *const u16;
    // used.idx at +0x02 (u16 offset 1).
    // SAFETY: HHDM maps this programmed split-queue used ring frame; used.idx
    // is an aligned u16 field.
    unsafe { core::ptr::read_volatile(used.add(1)) }
}

struct MappedTransportPage {
    page_pa: u64,
    mapping: mmio_map::Mapping,
}

#[derive(Default)]
pub(super) struct TransportMappings {
    pages: Vec<MappedTransportPage>,
}

impl TransportMappings {
    pub(super) fn map_page(&mut self, page_pa: u64) -> u64 {
        if page_pa == 0 {
            return 0;
        }
        for page in &self.pages {
            if page.page_pa == page_pa {
                return page.mapping.base_va();
            }
        }
        // SAFETY: virtio-pci decoded this page from a BAR capability owned by
        // the bound transport. The owned Mapping is kept until probe failure or
        // child remove quiesces the device.
        let mapping = unsafe { mmio_map::map_owned(page_pa, 1) };
        let base_va = mapping.base_va();
        self.pages.push(MappedTransportPage { page_pa, mapping });
        base_va
    }

    pub(super) fn unmap_all(&mut self) {
        self.pages.clear();
    }

    pub(super) fn map_queue_notify_va(
        &mut self,
        notify_cap: Option<&virtio::VirtioPciCap>,
        bars: &[pci::Bar; 6],
        notify_off: u16,
    ) -> u64 {
        let Some(notify_cap) = notify_cap else {
            return 0;
        };
        let Some(nfy_pa) = virtio::notify_pa(notify_cap, bars, notify_off) else {
            return 0;
        };
        let n_page_pa = nfy_pa & !0xFFF;
        let n_page_off = nfy_pa - n_page_pa;
        self.map_page(n_page_pa) + n_page_off
    }

    pub(super) fn read_isr_status(
        &mut self,
        isr_cap: Option<&virtio::VirtioPciCap>,
        bars: &[pci::Bar; 6],
    ) -> u8 {
        let Some(isr_cap) = isr_cap else {
            return 0;
        };
        let Some(ibar_pa) = bars.get(isr_cap.bar as usize).and_then(|bar| bar.mem_base()) else {
            return 0;
        };
        let isr_pa = ibar_pa + isr_cap.offset as u64;
        let page_pa = isr_pa & !0xFFF;
        let page_off = isr_pa - page_pa;
        let isr_va = self.map_page(page_pa) + page_off;
        // SAFETY: isr_va is decoded from the virtio-pci ISR capability and
        // mapped as Device memory by the transport mapping owner. The ISR byte
        // is a read-to-clear u8 register.
        unsafe { core::ptr::read_volatile(isr_va as *const u8) }
    }
}

pub(super) fn kick_queue_notify(notify_va: u64, queue_index: u16) -> bool {
    if notify_va == 0 {
        return false;
    }
    // SAFETY: notify_va is a Device-attr virtio notify location decoded from
    // the transport NOTIFY cap. Modern virtio-pci notify stores are u16 queue
    // indexes at the per-queue notify address.
    unsafe {
        core::ptr::write_volatile(notify_va as *mut u16, queue_index);
    }
    true
}
