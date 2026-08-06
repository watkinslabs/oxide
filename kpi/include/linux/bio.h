#ifndef OXIDE_LINUX_BIO_H
#define OXIDE_LINUX_BIO_H

#include <linux/blk_types.h>
#include <linux/gfp.h>
#include <linux/mm.h>

struct bio *bio_alloc(gfp_t gfp_mask, unsigned int nr_iovecs);
struct bio *bio_alloc_bioset(gfp_t gfp_mask, unsigned int nr_iovecs, void *bs);
void bio_init(struct bio *bio, struct block_device *bdev, struct bio_vec *table, unsigned int nr_vecs, u32 opf);
void bio_put(struct bio *bio);
void bio_set_dev(struct bio *bio, struct block_device *bdev);
int bio_add_page(struct bio *bio, struct page *page, unsigned int len, unsigned int off);
void __bio_add_page(struct bio *bio, struct page *page, unsigned int len, unsigned int off);
int submit_bio(struct bio *bio);
void submit_bio_noacct(struct bio *bio);
int submit_bio_wait(struct bio *bio);
void bio_endio(struct bio *bio);
void bio_chain(struct bio *bio, struct bio *parent);
struct bio *bio_split_to_limits(struct bio *bio);
int bio_associate_blkg(struct bio *bio);
void *bio_blkcg_css(struct bio *bio);
void zero_fill_bio_iter(struct bio *bio);

#endif
