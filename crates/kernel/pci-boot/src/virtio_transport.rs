//! Virtio-pci transport MMIO mapping and notify helpers.
//!
//! This module owns BAR-derived transport mappings used by virtio-pci probe
//! and runtime records. It keeps mapping lifetime separate from device-specific
//! child probe logic.

use alloc::vec::Vec;

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
