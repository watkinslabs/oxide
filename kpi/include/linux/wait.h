#ifndef OXIDE_LINUX_WAIT_H
#define OXIDE_LINUX_WAIT_H

typedef struct { unsigned int seq; } wait_queue_head_t;

void init_waitqueue_head(wait_queue_head_t *wq);
void wake_up(wait_queue_head_t *wq);
void wake_up_all(wait_queue_head_t *wq);
int waitqueue_active(wait_queue_head_t *wq);

#endif
