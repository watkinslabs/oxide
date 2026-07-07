#ifndef OXIDE_LINUX_BLK_MQ_H
#define OXIDE_LINUX_BLK_MQ_H

#include <linux/blkdev.h>

#define BLK_MQ_NO_HCTX_IDX ((unsigned int)-1)
#define BLK_MQ_REQ_NOWAIT   (1U << 0)
#define BLK_MQ_REQ_RESERVED (1U << 1)
#define BLK_MQ_REQ_PM       (1U << 2)

struct blk_mq_hw_ctx {
    struct request_queue *queue;
    void *driver_data;
    unsigned int queue_num;
    unsigned int nr_ctx;
};

struct blk_mq_queue_data {
    struct request *rq;
    bool last;
};

struct io_comp_batch;

struct blk_mq_ops {
    blk_status_t (*queue_rq)(struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data *bd);
    void (*commit_rqs)(struct blk_mq_hw_ctx *hctx);
    void *queue_rqs;
    int (*get_budget)(struct request_queue *q);
    void (*put_budget)(struct request_queue *q, int budget_token);
    void (*set_rq_budget_token)(struct request *rq, int token);
    int (*get_rq_budget_token)(struct request *rq);
    void *timeout;
    void *poll;
    void (*complete)(struct request *rq);
    void *init_hctx;
    void *exit_hctx;
    int (*init_request)(struct blk_mq_tag_set *set, struct request *rq, unsigned int hctx_idx, unsigned int numa_node);
    void (*exit_request)(struct blk_mq_tag_set *set, struct request *rq, unsigned int hctx_idx);
    void (*cleanup_rq)(struct request *rq);
    bool (*busy)(struct request_queue *q);
    void (*map_queues)(struct blk_mq_tag_set *set);
    void *show_rq;
};

struct gendisk *__blk_mq_alloc_disk(struct blk_mq_tag_set *set, struct queue_limits *lim, void *queuedata, void *lkclass);
#define blk_mq_alloc_disk(set, lim, queuedata) __blk_mq_alloc_disk((set), (lim), (queuedata), NULL)

struct request *blk_mq_alloc_request(struct request_queue *q, blk_opf_t opf, blk_mq_req_flags_t flags);
struct request *blk_mq_alloc_request_hctx(struct request_queue *q, blk_opf_t opf, blk_mq_req_flags_t flags, unsigned int hctx_idx);
void blk_mq_free_request(struct request *rq);
void blk_mq_start_request(struct request *rq);
void blk_mq_end_request(struct request *rq, blk_status_t error);
void __blk_mq_end_request(struct request *rq, blk_status_t error);
void blk_mq_end_request_batch(struct io_comp_batch *ib);
bool blk_update_request(struct request *rq, blk_status_t error, unsigned int nr_bytes);
void blk_execute_rq_nowait(struct request *rq, bool at_head);
blk_status_t blk_execute_rq(struct request *rq, bool at_head);
void blk_mq_requeue_request(struct request *rq, bool kick_requeue_list);
void blk_mq_freeze_queue_nomemsave(struct request_queue *q);
void blk_mq_unfreeze_queue_nomemrestore(struct request_queue *q);
void blk_freeze_queue_start(struct request_queue *q);
void blk_freeze_queue_start_non_owner(struct request_queue *q);
void blk_mq_freeze_queue_wait(struct request_queue *q);
void blk_mq_quiesce_queue(struct request_queue *q);
void blk_mq_unquiesce_queue(struct request_queue *q);
void blk_mq_quiesce_tagset(struct blk_mq_tag_set *set);
void blk_mq_unquiesce_tagset(struct blk_mq_tag_set *set);
void blk_mq_delay_kick_requeue_list(struct request_queue *q, unsigned int msecs);
void blk_mq_start_stopped_hw_queues(struct request_queue *q, bool async);
void blk_mq_stop_hw_queues(struct request_queue *q);
void blk_mq_update_nr_hw_queues(struct blk_mq_tag_set *set, unsigned int nr_hw_queues);
void blk_mq_map_queues(struct blk_mq_tag_set *set);
void blk_mq_map_hw_queues(void *map, void *dev, unsigned int offset);
unsigned int blk_mq_unique_tag(struct request *rq);

#endif
