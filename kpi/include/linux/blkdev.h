#ifndef OXIDE_LINUX_BLKDEV_H
#define OXIDE_LINUX_BLKDEV_H

#include <linux/bio.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/module.h>

typedef int (*make_request_fn)(struct request_queue *q, struct bio *bio);
typedef void (*request_fn_proc)(struct request_queue *q);

struct request_queue {
    make_request_fn make_request_fn;
    request_fn_proc request_fn;
    void *queuedata;
    u32 logical_block_size;
};

struct block_device {
    struct gendisk *bd_disk;
    struct request_queue *bd_queue;
    void *bd_private;
};

struct block_device_operations {
    struct module *owner;
    int (*open)(struct block_device *bdev, unsigned int mode);
    void (*release)(struct gendisk *disk, unsigned int mode);
    int (*ioctl)(struct block_device *bdev, unsigned int cmd, unsigned long arg);
};

struct request {
    struct request_queue *q;
    struct bio *bio;
    u32 cmd_flags;
};

struct blk_mq_tag_set {
    const void *ops;
    unsigned int nr_hw_queues;
    unsigned int queue_depth;
    int numa_node;
    unsigned int cmd_size;
    unsigned int flags;
    void *driver_data;
};

struct request_queue *blk_alloc_queue(gfp_t gfp_mask);
void blk_cleanup_queue(struct request_queue *q);
void blk_queue_make_request(struct request_queue *q, make_request_fn fn);
void blk_queue_logical_block_size(struct request_queue *q, unsigned int size);
int blk_mq_alloc_tag_set(struct blk_mq_tag_set *set);
void blk_mq_free_tag_set(struct blk_mq_tag_set *set);
struct request_queue *blk_mq_init_queue(struct blk_mq_tag_set *set);

#endif
