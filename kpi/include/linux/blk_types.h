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
#define BLK_STS_IOERR ((blk_status_t)10u)

struct block_device;
struct gendisk;
struct request_queue;

struct bio {
    struct gendisk *bi_disk;
    struct block_device *bi_bdev;
    void *bi_private;
    sector_t bi_sector;
    u32 bi_opf;
    blk_status_t bi_status;
    u32 bi_size;
    u8 *bi_data;
    void *owner;
};

static inline unsigned int bio_op(const struct bio *bio)
{
    return bio->bi_opf;
}

#endif
