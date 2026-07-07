#ifndef OXIDE_LINUX_BIO_H
#define OXIDE_LINUX_BIO_H

#include <linux/blk_types.h>
#include <linux/gfp.h>
#include <linux/mm.h>

struct bio *bio_alloc(gfp_t gfp_mask, unsigned int nr_iovecs);
void bio_put(struct bio *bio);
void bio_set_dev(struct bio *bio, struct block_device *bdev);
int bio_add_page(struct bio *bio, struct page *page, unsigned int len, unsigned int off);
int submit_bio(struct bio *bio);

#endif
