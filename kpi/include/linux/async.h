#ifndef OXIDE_LINUX_ASYNC_H
#define OXIDE_LINUX_ASYNC_H

#include <linux/list.h>
#include <linux/types.h>

typedef u64 async_cookie_t;
typedef void (*async_func_t)(void *data, async_cookie_t cookie);
struct async_domain { struct list_head pending; unsigned int registered:1; };
#define ASYNC_DOMAIN(name) struct async_domain name = { .pending = LIST_HEAD_INIT(name.pending), .registered = 1 }
#define ASYNC_DOMAIN_EXCLUSIVE(name) struct async_domain name = { .pending = LIST_HEAD_INIT(name.pending), .registered = 0 }

async_cookie_t async_schedule_node_domain(async_func_t func, void *data, int node, struct async_domain *domain);
void async_synchronize_full(void);
void async_synchronize_full_domain(struct async_domain *domain);

#endif
