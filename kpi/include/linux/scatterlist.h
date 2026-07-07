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

struct sg_table {
    struct scatterlist *sgl;
    unsigned int nents;
    unsigned int orig_nents;
};

struct sg_page_iter {
    struct scatterlist *sg;
    unsigned int sg_pgoffset;
    unsigned int __nents;
    int __pg_advance;
};

#define SG_MITER_ATOMIC  (1U << 0)
#define SG_MITER_TO_SG   (1U << 1)
#define SG_MITER_FROM_SG (1U << 2)
#define SG_MITER_LOCAL   (1U << 3)

struct sg_mapping_iter {
    struct page *page;
    void *addr;
    size_t length;
    size_t consumed;
    struct sg_page_iter piter;
    unsigned int __offset;
    unsigned int __remaining;
    unsigned int __flags;
};

void sg_init_table(struct scatterlist *sg, unsigned int nents);
void sg_init_one(struct scatterlist *sg, const void *buf, unsigned int buflen);
void sg_set_buf(struct scatterlist *sg, const void *buf, unsigned int buflen);
void sg_set_page(struct scatterlist *sg, struct page *page, unsigned int len, unsigned int offset);
struct scatterlist *sg_next(struct scatterlist *sg);
int sg_alloc_table(struct sg_table *table, unsigned int nents, gfp_t flags);
void sg_free_table(struct sg_table *table);
size_t sg_copy_to_buffer(struct scatterlist *sgl, unsigned int nents, void *buf, size_t buflen);
void sg_miter_start(struct sg_mapping_iter *miter, struct scatterlist *sgl, unsigned int nents, unsigned int flags);
bool sg_miter_next(struct sg_mapping_iter *miter);
void sg_miter_stop(struct sg_mapping_iter *miter);
struct scatterlist *sgl_alloc_order(unsigned long long length, unsigned int order, bool chainable, gfp_t gfp, unsigned int *nent_p);
void sgl_free_n_order(struct scatterlist *sgl, int nents, int order);

#endif
