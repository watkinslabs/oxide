use core::ffi::c_void;
use crate::linux_alloc::LinuxPage;

/// Linux's `DMA_MAPPING_ERROR` is an all-ones `dma_addr_t`, never address 0.
/// Zero is a valid device-visible address on direct-mapped platforms.
pub(crate) const DMA_MAPPING_ERROR: u64 = u64::MAX;
pub(crate) const LINUX_OK: i32 = 0;
pub(crate) const LINUX_EIO: i32 = 5;
pub(crate) const LINUX_EINVAL: i32 = 22;
pub(crate) const LINUX_ENOMEM: i32 = 12;
pub(crate) const DMA_NONE: i32 = 0;
pub(crate) const DMA_TO_DEVICE: i32 = 1;
pub(crate) const DMA_FROM_DEVICE: i32 = 2;
pub(crate) const DMA_BIDIRECTIONAL: i32 = 3;
pub(crate) const DEFAULT_DMA_MASK: u64 = u64::MAX;
pub(crate) const DMA_ADDRESS_BITS: u32 = u64::BITS;
/// Both active x86 IOMMU backends allocate from a 48-bit IOVA aperture.
pub(crate) const MAX_DMA_MAPPING_BYTES: usize = 1usize << 48;
pub(crate) const DMA_ATTR_SKIP_CPU_SYNC: u64 = 1 << 5;
pub(crate) const DMA_ATTR_NO_KERNEL_MAPPING: u64 = 1 << 4;
pub(crate) const SG_END: usize = 0x02;
// Only `linux_dma_tests` drives `sg_miter_start`; no in-tree module maps an SG
// list yet, so the direction flag has no production reader.
#[cfg(test)]
pub(crate) const SG_MITER_FROM_SG: u32 = 1 << 2;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ScatterList {
    pub(crate) page_link: usize,
    pub(crate) offset: u32,
    pub(crate) length: u32,
    pub(crate) dma_address: u64,
    pub(crate) dma_length: u32,
}

#[repr(C)]
pub struct SgTable {
    pub(crate) sgl: *mut ScatterList,
    pub(crate) nents: u32,
    pub(crate) orig_nents: u32,
}

#[repr(C)]
pub struct SgPageIter {
    pub(crate) sg: *mut ScatterList,
    pub(crate) sg_pgoffset: u32,
    pub(crate) nents: u32,
    pub(crate) pg_advance: i32,
}

#[repr(C)]
pub struct SgMappingIter {
    pub(crate) page: *mut LinuxPage,
    pub(crate) addr: *mut c_void,
    pub(crate) length: usize,
    pub(crate) consumed: usize,
    pub(crate) piter: SgPageIter,
    pub(crate) offset: u32,
    pub(crate) remaining: u32,
    pub(crate) flags: u32,
}

