//! Retained RTL8125 DMA allocation and IOMMU ownership.

use crate::regs;

const PAGE: usize = 4096;
const RX_ORDER: pmm::Order = pmm::Order(10);
const TX_ORDER: pmm::Order = pmm::Order(10);

/// CPU physical backing and requester-keyed device mappings for one RTL8125.
pub struct Rings { pub rx_desc_pa: u64, pub tx_desc_pa: u64, pub rx_data_pa: u64, pub tx_data_pa: u64, pub rx_desc_dma: u64, pub tx_desc_dma: u64, pub rx_data_dma: u64, pub tx_data_dma: u64, bdf: pci::Bdf }
impl Rings {
    /// Allocate, map, and retain every descriptor and packet DMA object. # C: O(ring bytes)
    pub fn allocate(bdf: pci::Bdf) -> Option<Self> {
        let rx_desc_pa = pmm::setup::alloc_contig(pmm::Order(0))?;
        let tx_desc_pa = match pmm::setup::alloc_contig(pmm::Order(0)) { Some(pa) => pa, None => { free(rx_desc_pa, pmm::Order(0)); return None; } };
        let rx_data_pa = match pmm::setup::alloc_contig(RX_ORDER) { Some(pa) => pa, None => { free_all(rx_desc_pa, tx_desc_pa, 0, 0); return None; } };
        let tx_data_pa = match pmm::setup::alloc_contig(TX_ORDER) { Some(pa) => pa, None => { free_all(rx_desc_pa, tx_desc_pa, rx_data_pa, 0); return None; } };
        let rx_desc_dma = match iommu::map_dma(bdf, rx_desc_pa, PAGE) { Some(dma) => dma, None => { free_all(rx_desc_pa, tx_desc_pa, rx_data_pa, tx_data_pa); return None; } };
        let tx_desc_dma = match iommu::map_dma(bdf, tx_desc_pa, PAGE) { Some(dma) => dma, None => { let _ = iommu::unmap_dma(bdf, rx_desc_dma, PAGE); free_all(rx_desc_pa, tx_desc_pa, rx_data_pa, tx_data_pa); return None; } };
        let rx_data_dma = match iommu::map_dma(bdf, rx_data_pa, bytes(RX_ORDER)) { Some(dma) => dma, None => { let _ = iommu::unmap_dma(bdf, rx_desc_dma, PAGE); let _ = iommu::unmap_dma(bdf, tx_desc_dma, PAGE); free_all(rx_desc_pa, tx_desc_pa, rx_data_pa, tx_data_pa); return None; } };
        let tx_data_dma = match iommu::map_dma(bdf, tx_data_pa, bytes(TX_ORDER)) { Some(dma) => dma, None => { let _ = iommu::unmap_dma(bdf, rx_desc_dma, PAGE); let _ = iommu::unmap_dma(bdf, tx_desc_dma, PAGE); let _ = iommu::unmap_dma(bdf, rx_data_dma, bytes(RX_ORDER)); free_all(rx_desc_pa, tx_desc_pa, rx_data_pa, tx_data_pa); return None; } };
        Some(Self { rx_desc_pa, tx_desc_pa, rx_data_pa, tx_data_pa, rx_desc_dma, tx_desc_dma, rx_data_dma, tx_data_dma, bdf })
    }
    /// Populate receive descriptors with device DMA addresses before engine enable. # C: O(ring bytes)
    pub fn initialize_rx(&self) -> bool { for index in 0..regs::RING_COUNT { let va = hhdm(self.rx_desc_pa + (index * core::mem::size_of::<regs::RxDesc>()) as u64); // SAFETY: this retained descriptor backing is private until engine enable.
        unsafe { (va as *mut regs::RxDesc).write(regs::rx_descriptor(self.rx_data_dma + (index * regs::BUFFER_BYTES) as u64, index + 1 == regs::RING_COUNT)); } }
        pmm::dma::clean_to_device(hhdm(self.rx_desc_pa), regs::RING_BYTES); true }
    /// Retire mappings before returning physical backing to PMM. # C: O(1)
    pub fn release(self) { let _ = iommu::unmap_dma(self.bdf, self.rx_desc_dma, PAGE); let _ = iommu::unmap_dma(self.bdf, self.tx_desc_dma, PAGE); let _ = iommu::unmap_dma(self.bdf, self.rx_data_dma, bytes(RX_ORDER)); let _ = iommu::unmap_dma(self.bdf, self.tx_data_dma, bytes(TX_ORDER)); free_all(self.rx_desc_pa, self.tx_desc_pa, self.rx_data_pa, self.tx_data_pa); }
}
fn bytes(order: pmm::Order) -> usize { (1usize << order.0) * PAGE }
fn hhdm(pa: u64) -> u64 { pmm::user_as::hhdm_offset().wrapping_add(pa) }
fn free(pa: u64, order: pmm::Order) { if pa != 0 { // SAFETY: caller owns an unpublished contiguous PMM allocation.
    unsafe { pmm::setup::free_contig(pa, order); } } }
fn free_all(rx_desc: u64, tx_desc: u64, rx_data: u64, tx_data: u64) { free(rx_desc, pmm::Order(0)); free(tx_desc, pmm::Order(0)); free(rx_data, RX_ORDER); free(tx_data, TX_ORDER); }
