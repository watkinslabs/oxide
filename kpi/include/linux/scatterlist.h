#ifndef OXIDE_LINUX_SCATTERLIST_H
#define OXIDE_LINUX_SCATTERLIST_H

#include <linux/types.h>

struct scatterlist {
    unsigned long page_link;
    unsigned int offset;
    unsigned int length;
    dma_addr_t dma_address;
    unsigned int dma_length;
};

#define sg_dma_address(sg) ((sg)->dma_address)
#define sg_dma_len(sg) ((sg)->dma_length)

void sg_init_table(struct scatterlist *sg, unsigned int nents);
void sg_init_one(struct scatterlist *sg, const void *buf, unsigned int buflen);
void sg_set_buf(struct scatterlist *sg, const void *buf, unsigned int buflen);
void sg_set_page(struct scatterlist *sg, struct page *page, unsigned int len, unsigned int offset);
struct scatterlist *sg_next(struct scatterlist *sg);

#endif
