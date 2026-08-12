//! IGC queue DMA allocation and IOMMU mapping ownership.

use crate::{queue, regs};

const PAGE: usize = 4096;
const DATA_ORDER: pmm::Order = pmm::Order(7);

pub struct Rings {
    bdf: pci::Bdf,
    rx_desc_pa: u64, tx_desc_pa: u64, rx_data_pa: u64, tx_data_pa: u64,
    rx_desc_dma: u64, tx_desc_dma: u64, rx_data_dma: u64, tx_data_dma: u64,
}

impl Rings {
    /// Allocates unmapped IGC ring memory and maps each device-owned span.
    /// # C: O(1)
    pub fn allocate(bdf: pci::Bdf) -> Option<Self> {
        let rx_desc_pa = pmm::setup::alloc_contig(pmm::Order(0))?;
        let Some(tx_desc_pa) = pmm::setup::alloc_contig(pmm::Order(0)) else { free(rx_desc_pa, pmm::Order(0)); return None; };
        let Some(rx_data_pa) = pmm::setup::alloc_contig(DATA_ORDER) else { free(rx_desc_pa, pmm::Order(0)); free(tx_desc_pa, pmm::Order(0)); return None; };
        let Some(tx_data_pa) = pmm::setup::alloc_contig(DATA_ORDER) else { free(rx_desc_pa, pmm::Order(0)); free(tx_desc_pa, pmm::Order(0)); free(rx_data_pa, DATA_ORDER); return None; };
        let Some(rx_desc_dma) = iommu::map_dma(bdf, rx_desc_pa, PAGE) else { free_all(rx_desc_pa, tx_desc_pa, rx_data_pa, tx_data_pa); return None; };
        let Some(tx_desc_dma) = iommu::map_dma(bdf, tx_desc_pa, PAGE) else { let _ = iommu::unmap_dma(bdf, rx_desc_dma, PAGE); free_all(rx_desc_pa, tx_desc_pa, rx_data_pa, tx_data_pa); return None; };
        let data_bytes = data_bytes();
        let Some(rx_data_dma) = iommu::map_dma(bdf, rx_data_pa, data_bytes) else { let _ = iommu::unmap_dma(bdf, rx_desc_dma, PAGE); let _ = iommu::unmap_dma(bdf, tx_desc_dma, PAGE); free_all(rx_desc_pa, tx_desc_pa, rx_data_pa, tx_data_pa); return None; };
        let Some(tx_data_dma) = iommu::map_dma(bdf, tx_data_pa, data_bytes) else { let _ = iommu::unmap_dma(bdf, rx_desc_dma, PAGE); let _ = iommu::unmap_dma(bdf, tx_desc_dma, PAGE); let _ = iommu::unmap_dma(bdf, rx_data_dma, data_bytes); free_all(rx_desc_pa, tx_desc_pa, rx_data_pa, tx_data_pa); return None; };
        Some(Self { bdf, rx_desc_pa, tx_desc_pa, rx_data_pa, tx_data_pa, rx_desc_dma, tx_desc_dma, rx_data_dma, tx_data_dma })
    }

    /// Initializes every descriptor before the queue is made visible to hardware.
    /// # C: O(N)
    pub fn initialize(&self) {
        for index in 0..queue::RING_COUNT {
            // SAFETY: these rings are private, initialized allocation before controller queue enable.
            unsafe { *self.rx_desc(index) = regs::AdvRxDesc { packet_addr: self.rx_buffer_dma(index), header_addr: 0 }; *self.tx_desc(index) = regs::AdvTxDesc::default(); }
        }
        pmm::dma::clean_to_device(self.rx_desc_va(), queue::RING_COUNT * core::mem::size_of::<regs::AdvRxDesc>());
        pmm::dma::clean_to_device(self.tx_desc_va(), queue::RING_COUNT * core::mem::size_of::<regs::AdvTxDesc>());
        pmm::dma::invalidate_from_device(self.rx_data_va(), data_bytes());
    }

    /// Returns the receive descriptor-ring IOVA.
    /// # C: O(1)
    pub const fn rx_desc_dma(&self) -> u64 { self.rx_desc_dma }
    /// Returns the transmit descriptor-ring IOVA.
    /// # C: O(1)
    pub const fn tx_desc_dma(&self) -> u64 { self.tx_desc_dma }
    /// Returns the receive descriptor VA for a bounded slot.
    /// # C: O(1)
    pub fn rx_desc(&self, index: usize) -> *mut regs::AdvRxDesc { (self.rx_desc_va() as *mut regs::AdvRxDesc).wrapping_add(index % queue::RING_COUNT) }
    /// Returns the transmit descriptor VA for a bounded slot.
    /// # C: O(1)
    pub fn tx_desc(&self, index: usize) -> *mut regs::AdvTxDesc { (self.tx_desc_va() as *mut regs::AdvTxDesc).wrapping_add(index % queue::RING_COUNT) }
    /// Returns the receive descriptor VA for device cache maintenance.
    /// # C: O(1)
    pub fn rx_desc_slot_va(&self, index: usize) -> u64 { self.rx_desc_va() + (index % queue::RING_COUNT * core::mem::size_of::<regs::AdvRxDesc>()) as u64 }
    /// Returns the transmit descriptor VA for device cache maintenance.
    /// # C: O(1)
    pub fn tx_desc_slot_va(&self, index: usize) -> u64 { self.tx_desc_va() + (index % queue::RING_COUNT * core::mem::size_of::<regs::AdvTxDesc>()) as u64 }
    /// Returns the receive data IOVA for a bounded slot.
    /// # C: O(1)
    pub fn rx_buffer_dma(&self, index: usize) -> u64 { self.rx_data_dma + (index % queue::RING_COUNT * queue::BUFFER_BYTES) as u64 }
    /// Returns the transmit data IOVA for a bounded slot.
    /// # C: O(1)
    pub fn tx_buffer_dma(&self, index: usize) -> u64 { self.tx_data_dma + (index % queue::RING_COUNT * queue::BUFFER_BYTES) as u64 }
    /// Returns the receive data VA for a bounded slot.
    /// # C: O(1)
    pub fn rx_buffer_va(&self, index: usize) -> u64 { self.rx_data_va() + (index % queue::RING_COUNT * queue::BUFFER_BYTES) as u64 }
    /// Returns the transmit data VA for a bounded slot.
    /// # C: O(1)
    pub fn tx_buffer_va(&self, index: usize) -> u64 { self.tx_data_va() + (index % queue::RING_COUNT * queue::BUFFER_BYTES) as u64 }
    /// Returns every mapping and allocation after the controller has stopped DMA.
    /// # C: O(1)
    pub fn release(self) {
        let data_bytes = data_bytes();
        let _ = iommu::unmap_dma(self.bdf, self.rx_desc_dma, PAGE); let _ = iommu::unmap_dma(self.bdf, self.tx_desc_dma, PAGE);
        let _ = iommu::unmap_dma(self.bdf, self.rx_data_dma, data_bytes); let _ = iommu::unmap_dma(self.bdf, self.tx_data_dma, data_bytes);
        free_all(self.rx_desc_pa, self.tx_desc_pa, self.rx_data_pa, self.tx_data_pa);
    }

    fn rx_desc_va(&self) -> u64 { va(self.rx_desc_pa) }
    fn tx_desc_va(&self) -> u64 { va(self.tx_desc_pa) }
    fn rx_data_va(&self) -> u64 { va(self.rx_data_pa) }
    fn tx_data_va(&self) -> u64 { va(self.tx_data_pa) }
}

fn data_bytes() -> usize { (1usize << DATA_ORDER.0) * PAGE }
fn va(pa: u64) -> u64 { pmm::user_as::hhdm_offset().wrapping_add(pa) }
fn free_all(rx_desc: u64, tx_desc: u64, rx_data: u64, tx_data: u64) { free(rx_desc, pmm::Order(0)); free(tx_desc, pmm::Order(0)); free(rx_data, DATA_ORDER); free(tx_data, DATA_ORDER); }
fn free(pa: u64, order: pmm::Order) { // SAFETY: every caller owns an unpublished PMM allocation of this exact order.
    unsafe { pmm::setup::free_contig(pa, order); }
}
