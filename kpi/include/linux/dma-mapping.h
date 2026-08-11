#ifndef OXIDE_LINUX_DMA_MAPPING_H
#define OXIDE_LINUX_DMA_MAPPING_H

#include <linux/device.h>
#include <linux/gfp.h>
#include <linux/scatterlist.h>
#include <linux/stddef.h>
#include <linux/types.h>

#define DMA_MAPPING_ERROR 0
#define DMA_ULL_BITS (__SIZEOF_LONG_LONG__ * __CHAR_BIT__)
#define DMA_BIT_MASK(n) ((n) >= DMA_ULL_BITS ? ~0ULL : ((1ULL << ((n) & (DMA_ULL_BITS - 1))) - 1ULL))

enum dma_data_direction {
    DMA_NONE = 0,
    DMA_TO_DEVICE = 1,
    DMA_FROM_DEVICE = 2,
    DMA_BIDIRECTIONAL = 3,
};

void *dma_alloc_coherent(struct device *dev, size_t size, dma_addr_t *dma_handle, gfp_t flag);
void dma_free_coherent(struct device *dev, size_t size, void *cpu_addr, dma_addr_t dma_handle);
dma_addr_t dma_map_single(struct device *dev, void *ptr, size_t size, enum dma_data_direction dir);
void dma_unmap_single(struct device *dev, dma_addr_t dma_addr, size_t size, enum dma_data_direction dir);
dma_addr_t dma_map_page(struct device *dev, struct page *page, unsigned long offset, size_t size, enum dma_data_direction dir);
void dma_unmap_page(struct device *dev, dma_addr_t dma_addr, size_t size, enum dma_data_direction dir);
int dma_map_sg(struct device *dev, struct scatterlist *sg, int nents, enum dma_data_direction dir);
void dma_unmap_sg(struct device *dev, struct scatterlist *sg, int nents, enum dma_data_direction dir);
int dma_mapping_error(struct device *dev, dma_addr_t dma_addr);
void *dmam_alloc_attrs(struct device *dev, size_t size, dma_addr_t *dma_handle, gfp_t gfp, unsigned long attrs);
void *dmam_alloc_coherent(struct device *dev, size_t size, dma_addr_t *dma_handle, gfp_t gfp);
void dmam_free_coherent(struct device *dev, size_t size, void *vaddr, dma_addr_t dma_handle);
void dma_sync_single_for_cpu(struct device *dev, dma_addr_t dma_handle, size_t size, enum dma_data_direction dir);
void dma_sync_single_for_device(struct device *dev, dma_addr_t dma_handle, size_t size, enum dma_data_direction dir);
void __dma_sync_single_for_cpu(struct device *dev, dma_addr_t dma_handle, size_t size, enum dma_data_direction dir);
void __dma_sync_single_for_device(struct device *dev, dma_addr_t dma_handle, size_t size, enum dma_data_direction dir);
void dma_sync_sg_for_cpu(struct device *dev, struct scatterlist *sg, int nelems, enum dma_data_direction dir);
void dma_sync_sg_for_device(struct device *dev, struct scatterlist *sg, int nelems, enum dma_data_direction dir);
int dma_set_mask(struct device *dev, u64 mask);
int dma_set_coherent_mask(struct device *dev, u64 mask);
int dma_set_mask_and_coherent(struct device *dev, u64 mask);
int dma_supported(struct device *dev, u64 mask);
u64 dma_get_required_mask(struct device *dev);

static inline void *dma_zalloc_coherent(struct device *dev, size_t size, dma_addr_t *dma_handle, gfp_t flag)
{
    return dma_alloc_coherent(dev, size, dma_handle, flag);
}

#endif
