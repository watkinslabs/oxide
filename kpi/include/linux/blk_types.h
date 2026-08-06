#ifndef OXIDE_LINUX_BLK_TYPES_H
#define OXIDE_LINUX_BLK_TYPES_H

#include <linux/types.h>

typedef u64 sector_t;
typedef u8 blk_status_t;
typedef int blk_qc_t;

#define SECTOR_SHIFT 9u
#define SECTOR_SIZE (1u << SECTOR_SHIFT)

#define REQ_OP_READ 0u
#define REQ_OP_WRITE 1u
#define REQ_OP_FLUSH 2u
#define REQ_OP_DISCARD 3u

#define BLK_STS_OK ((blk_status_t)0u)
#define BLK_STS_RESOURCE ((blk_status_t)1u)
#define BLK_STS_AGAIN ((blk_status_t)2u)
#define BLK_STS_NOTSUPP ((blk_status_t)9u)
#define BLK_STS_IOERR ((blk_status_t)10u)
#define BLK_STS_TARGET ((blk_status_t)11u)

struct block_device;
struct gendisk;
struct page;
struct request_queue;

struct bio_vec {
    struct page *bv_page;
    u32 bv_len;
    u32 bv_offset;
};

struct bio {
    struct gendisk *bi_disk;
    struct block_device *bi_bdev;
    void *bi_private;
    sector_t bi_sector;
    u32 bi_opf;
    blk_status_t bi_status;
    u32 bi_size;
    struct bio_vec *bi_io_vec;
    unsigned short bi_vcnt;
    unsigned short bi_max_vecs;
    void (*bi_end_io)(struct bio *bio);
    void *owner;
};

_Static_assert(sizeof(struct bio_vec) == 16, "bio_vec ABI size");
_Static_assert(sizeof(struct bio) == 80, "bio ABI size");
_Static_assert(__builtin_offsetof(struct bio, bi_size) == 40, "bio bi_size offset");
_Static_assert(__builtin_offsetof(struct bio, bi_io_vec) == 48, "bio bi_io_vec offset");
_Static_assert(__builtin_offsetof(struct bio, bi_vcnt) == 56, "bio bi_vcnt offset");
_Static_assert(__builtin_offsetof(struct bio, bi_end_io) == 64, "bio bi_end_io offset");

static inline unsigned int bio_op(const struct bio *bio)
{
    return bio->bi_opf;
}

#endif
