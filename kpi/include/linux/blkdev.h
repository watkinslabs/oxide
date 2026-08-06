#ifndef OXIDE_LINUX_BLKDEV_H
#define OXIDE_LINUX_BLKDEV_H

#include <linux/bio.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/module.h>

typedef int (*make_request_fn)(struct request_queue *q, struct bio *bio);
typedef void (*request_fn_proc)(struct request_queue *q);
typedef u32 blk_opf_t;
typedef u32 blk_mq_req_flags_t;

struct blk_mq_ops;
struct blk_mq_tag_set;
struct io_comp_batch;

struct queue_limits {
    u32 logical_block_size;
    u32 physical_block_size;
    u32 io_min;
    u32 io_opt;
    u32 max_hw_sectors;
    u32 max_segments;
    u32 discard_granularity;
    u32 discard_alignment;
};

struct request_queue {
    make_request_fn make_request_fn;
    request_fn_proc request_fn;
    void *queuedata;
    u32 logical_block_size;
    const struct blk_mq_ops *mq_ops;
    struct blk_mq_tag_set *tag_set;
    struct gendisk *disk;
    u32 rq_timeout;
    u32 nr_hw_queues;
    u32 freeze_depth;
    u32 quiesce_depth;
    struct queue_limits limits;
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
    void *mq_ctx;
    void *mq_hctx;
    struct bio *bio;
    struct bio *biotail;
    blk_opf_t cmd_flags;
    u32 rq_flags;
    int tag;
    int internal_tag;
    u32 timeout;
    u32 __data_len;
    sector_t __sector;
    struct block_device *part;
    u32 state;
    blk_status_t status;
    int (*end_io)(struct request *rq, blk_status_t error, const struct io_comp_batch *iob);
    void *end_io_data;
    struct request *rq_next;
};

struct rq_list {
    struct request *head;
    struct request *tail;
};

struct io_comp_batch {
    struct rq_list req_list;
    bool need_ts;
    void (*complete)(struct io_comp_batch *iob);
    void *poll_ctx;
};

_Static_assert(sizeof(struct request) == 112, "request ABI size");
_Static_assert(__builtin_offsetof(struct request, bio) == 24, "request bio offset");
_Static_assert(__builtin_offsetof(struct request, cmd_flags) == 40, "request cmd_flags offset");
_Static_assert(__builtin_offsetof(struct request, __sector) == 64, "request sector offset");
_Static_assert(__builtin_offsetof(struct request, end_io) == 88, "request end_io offset");
_Static_assert(__builtin_offsetof(struct request, rq_next) == 104, "request rq_next offset");
_Static_assert(sizeof(struct io_comp_batch) == 40, "io_comp_batch ABI size");
_Static_assert(__builtin_offsetof(struct io_comp_batch, complete) == 24, "io_comp_batch complete offset");

struct blk_mq_tag_set {
    const struct blk_mq_ops *ops;
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
struct gendisk *__blk_alloc_disk(struct queue_limits *lim, int node, void *lkclass);
struct request_queue *blk_mq_alloc_queue(struct blk_mq_tag_set *set, struct queue_limits *lim, void *queuedata);
void blk_mq_destroy_queue(struct request_queue *q);
void blk_put_queue(struct request_queue *q);
int bdev_disk_changed(struct gendisk *disk, bool invalidate);
int device_add_disk(struct device *parent, struct gendisk *disk, const void *groups);
void blk_mark_disk_dead(struct gendisk *disk);
void blk_queue_rq_timeout(struct request_queue *q, unsigned int timeout);
void blk_sync_queue(struct request_queue *q);
void blk_set_stacking_limits(struct queue_limits *lim);
int blk_revalidate_disk_zones(struct gendisk *disk, void *report);
const char *blk_op_str(unsigned int op);
int blk_status_to_errno(blk_status_t status);
blk_status_t errno_to_blk_status(int error);

#define blk_alloc_disk(lim, node_id) __blk_alloc_disk((lim), (node_id), NULL)

#endif
