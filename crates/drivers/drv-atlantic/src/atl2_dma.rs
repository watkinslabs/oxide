//! AQC113 queue DMA allocation and IOMMU mapping ownership.

use crate::{atl2_queue as queue, atl2_regs as regs};

const RX_DESC_ORDER: pmm::Order = pmm::Order(3);
const TX_DESC_ORDER: pmm::Order = pmm::Order(4);
const RX_DATA_ORDER: pmm::Order = pmm::Order(10);
const TX_DATA_ORDER: pmm::Order = pmm::Order(11);

pub struct Rings {
    bdf: pci::Bdf,
    rx_desc_pa: u64, tx_desc_pa: u64, rx_data_pa: u64, tx_data_pa: u64,
    rx_desc_dma: u64, tx_desc_dma: u64, rx_data_dma: u64, tx_data_dma: u64,
}

impl Rings {
    /// Allocates and maps the default one-queue AQC113 RX and TX regions.
    /// # C: O(1)
    pub fn allocate(bdf: pci::Bdf) -> Option<Self> {
        let rx_desc_pa = pmm::setup::alloc_contig(RX_DESC_ORDER)?;
        let Some(tx_desc_pa) = pmm::setup::alloc_contig(TX_DESC_ORDER) else { free(rx_desc_pa, RX_DESC_ORDER); return None; };
        let Some(rx_data_pa) = pmm::setup::alloc_contig(RX_DATA_ORDER) else { free_pair(rx_desc_pa, tx_desc_pa); return None; };
        let Some(tx_data_pa) = pmm::setup::alloc_contig(TX_DATA_ORDER) else { free_triple(rx_desc_pa, tx_desc_pa, rx_data_pa); return None; };
        let Some(rx_desc_dma) = iommu::map_dma(bdf, rx_desc_pa, ring_rx_bytes()) else { free_all(rx_desc_pa, tx_desc_pa, rx_data_pa, tx_data_pa); return None; };
        let Some(tx_desc_dma) = iommu::map_dma(bdf, tx_desc_pa, ring_tx_bytes()) else { let _ = iommu::unmap_dma(bdf, rx_desc_dma, ring_rx_bytes()); free_all(rx_desc_pa, tx_desc_pa, rx_data_pa, tx_data_pa); return None; };
        let Some(rx_data_dma) = iommu::map_dma(bdf, rx_data_pa, data_rx_bytes()) else { unmap_descriptors(bdf, rx_desc_dma, tx_desc_dma); free_all(rx_desc_pa, tx_desc_pa, rx_data_pa, tx_data_pa); return None; };
        let Some(tx_data_dma) = iommu::map_dma(bdf, tx_data_pa, data_tx_bytes()) else { unmap_descriptors(bdf, rx_desc_dma, tx_desc_dma); let _ = iommu::unmap_dma(bdf, rx_data_dma, data_rx_bytes()); free_all(rx_desc_pa, tx_desc_pa, rx_data_pa, tx_data_pa); return None; };
        Some(Self { bdf, rx_desc_pa, tx_desc_pa, rx_data_pa, tx_data_pa, rx_desc_dma, tx_desc_dma, rx_data_dma, tx_data_dma })
    }

    /// Initializes every descriptor before queue ownership is published to hardware.
    /// # C: O(N)
    pub fn initialize(&self) {
        for index in 0..queue::RX_RING_DEFAULT {
            // SAFETY: each descriptor slot is private before the queue enable publication.
            unsafe { *self.rx_desc(index) = regs::RxDesc { buffer_dma: self.rx_buffer_dma(index), header_dma: 0 }; }
        }
        for index in 0..queue::TX_RING_DEFAULT {
            // SAFETY: each descriptor slot is private before the queue enable publication.
            unsafe { *self.tx_desc(index) = regs::TxDesc::default(); }
        }
        pmm::dma::clean_to_device(self.rx_desc_va(), ring_rx_bytes());
        pmm::dma::clean_to_device(self.tx_desc_va(), ring_tx_bytes());
        pmm::dma::invalidate_from_device(self.rx_data_va(), data_rx_bytes());
    }

    /// Returns the receive descriptor-ring IOVA.
    /// # C: O(1)
    pub const fn rx_desc_dma(&self) -> u64 { self.rx_desc_dma }
    /// Returns the transmit descriptor-ring IOVA.
    /// # C: O(1)
    pub const fn tx_desc_dma(&self) -> u64 { self.tx_desc_dma }
    /// Returns a receive descriptor slot address bounded to the ring.
    /// # C: O(1)
    pub fn rx_desc(&self, index: usize) -> *mut regs::RxDesc { (self.rx_desc_va() as *mut regs::RxDesc).wrapping_add(index % queue::RX_RING_DEFAULT) }
    /// Returns a transmit descriptor slot address bounded to the ring.
    /// # C: O(1)
    pub fn tx_desc(&self, index: usize) -> *mut regs::TxDesc { (self.tx_desc_va() as *mut regs::TxDesc).wrapping_add(index % queue::TX_RING_DEFAULT) }
    /// Returns a receive descriptor slot VA for cache maintenance.
    /// # C: O(1)
    pub fn rx_desc_slot_va(&self, index: usize) -> u64 { self.rx_desc_va() + (index % queue::RX_RING_DEFAULT * core::mem::size_of::<regs::RxDesc>()) as u64 }
    /// Returns a transmit descriptor slot VA for cache maintenance.
    /// # C: O(1)
    pub fn tx_desc_slot_va(&self, index: usize) -> u64 { self.tx_desc_va() + (index % queue::TX_RING_DEFAULT * core::mem::size_of::<regs::TxDesc>()) as u64 }
    /// Returns the receive data IOVA for a bounded descriptor slot.
    /// # C: O(1)
    pub fn rx_buffer_dma(&self, index: usize) -> u64 { self.rx_data_dma + (index % queue::RX_RING_DEFAULT * queue::RX_BUFFER_BYTES) as u64 }
    /// Returns the transmit data IOVA for a bounded descriptor slot.
    /// # C: O(1)
    pub fn tx_buffer_dma(&self, index: usize) -> u64 { self.tx_data_dma + (index % queue::TX_RING_DEFAULT * queue::RX_BUFFER_BYTES) as u64 }
    /// Returns the receive backing-buffer VA for a bounded descriptor slot.
    /// # C: O(1)
    pub fn rx_buffer_va(&self, index: usize) -> u64 { self.rx_data_va() + (index % queue::RX_RING_DEFAULT * queue::RX_BUFFER_BYTES) as u64 }
    /// Returns the transmit backing-buffer VA for a bounded descriptor slot.
    /// # C: O(1)
    pub fn tx_buffer_va(&self, index: usize) -> u64 { self.tx_data_va() + (index % queue::TX_RING_DEFAULT * queue::RX_BUFFER_BYTES) as u64 }
    /// Returns each IOMMU mapping and PMM allocation after device DMA is disabled.
    /// # C: O(1)
    pub fn release(self) {
        unmap_descriptors(self.bdf, self.rx_desc_dma, self.tx_desc_dma);
        let _ = iommu::unmap_dma(self.bdf, self.rx_data_dma, data_rx_bytes());
        let _ = iommu::unmap_dma(self.bdf, self.tx_data_dma, data_tx_bytes());
        free_all(self.rx_desc_pa, self.tx_desc_pa, self.rx_data_pa, self.tx_data_pa);
    }

    fn rx_desc_va(&self) -> u64 { va(self.rx_desc_pa) }
    fn tx_desc_va(&self) -> u64 { va(self.tx_desc_pa) }
    fn rx_data_va(&self) -> u64 { va(self.rx_data_pa) }
    fn tx_data_va(&self) -> u64 { va(self.tx_data_pa) }
}

fn ring_rx_bytes() -> usize { queue::RX_RING_DEFAULT * core::mem::size_of::<regs::RxDesc>() }
fn ring_tx_bytes() -> usize { queue::TX_RING_DEFAULT * core::mem::size_of::<regs::TxDesc>() }
fn data_rx_bytes() -> usize { queue::RX_RING_DEFAULT * queue::RX_BUFFER_BYTES }
fn data_tx_bytes() -> usize { queue::TX_RING_DEFAULT * queue::RX_BUFFER_BYTES }
fn va(pa: u64) -> u64 { pmm::user_as::hhdm_offset().wrapping_add(pa) }
fn unmap_descriptors(bdf: pci::Bdf, rx_dma: u64, tx_dma: u64) { let _ = iommu::unmap_dma(bdf, rx_dma, ring_rx_bytes()); let _ = iommu::unmap_dma(bdf, tx_dma, ring_tx_bytes()); }
fn free_pair(rx_desc: u64, tx_desc: u64) { free(rx_desc, RX_DESC_ORDER); free(tx_desc, TX_DESC_ORDER); }
fn free_triple(rx_desc: u64, tx_desc: u64, rx_data: u64) { free_pair(rx_desc, tx_desc); free(rx_data, RX_DATA_ORDER); }
fn free_all(rx_desc: u64, tx_desc: u64, rx_data: u64, tx_data: u64) { free_triple(rx_desc, tx_desc, rx_data); free(tx_data, TX_DATA_ORDER); }
fn free(pa: u64, order: pmm::Order) {
    // SAFETY: caller owns this unpublished contiguous allocation at its exact order.
    unsafe { pmm::setup::free_contig(pa, order); }
}
