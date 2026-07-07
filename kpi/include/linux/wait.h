#ifndef OXIDE_LINUX_WAIT_H
#define OXIDE_LINUX_WAIT_H

typedef struct { unsigned int seq; } wait_queue_head_t;
typedef struct { unsigned int flags; void *private; void *func; unsigned int seq; } wait_queue_entry_t;
typedef struct { unsigned int seq; } swait_queue_head_t;

void init_waitqueue_head(wait_queue_head_t *wq);
void __init_waitqueue_head(wait_queue_head_t *wq, const char *name, void *key);
void __init_swait_queue_head(swait_queue_head_t *wq, const char *name, void *key);
void wake_up(wait_queue_head_t *wq);
int __wake_up(wait_queue_head_t *wq, unsigned int mode, int nr, void *key);
void wake_up_all(wait_queue_head_t *wq);
int waitqueue_active(wait_queue_head_t *wq);
void init_wait_entry(wait_queue_entry_t *wq_entry, int flags);
long prepare_to_wait_event(wait_queue_head_t *wq, wait_queue_entry_t *wq_entry, int state);
void finish_wait(wait_queue_head_t *wq, wait_queue_entry_t *wq_entry);

#endif
