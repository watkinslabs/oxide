#ifndef OXIDE_LINUX_LIST_H
#define OXIDE_LINUX_LIST_H

#include <linux/kernel.h>

struct list_head { struct list_head *next, *prev; };
struct hlist_node { struct hlist_node *next, **pprev; };
struct hlist_head { struct hlist_node *first; };

#define LIST_HEAD_INIT(name) { &(name), &(name) }
#define LIST_HEAD(name) struct list_head name = LIST_HEAD_INIT(name)
#define INIT_LIST_HEAD(ptr) do { (ptr)->next = (ptr); (ptr)->prev = (ptr); } while (0)
#define list_entry(ptr, type, member) container_of(ptr, type, member)
#define list_first_entry(ptr, type, member) list_entry((ptr)->next, type, member)
#define list_for_each(pos, head) for (pos = (head)->next; pos != (head); pos = pos->next)
#define list_for_each_entry(pos, head, member) for (pos = list_first_entry(head, typeof(*pos), member); &pos->member != (head); pos = list_entry(pos->member.next, typeof(*pos), member))

static __always_inline void __list_add(struct list_head *n, struct list_head *prev, struct list_head *next)
{
    next->prev = n; n->next = next; n->prev = prev; prev->next = n;
}

static __always_inline void list_add(struct list_head *n, struct list_head *head)
{
    __list_add(n, head, head->next);
}

static __always_inline void list_add_tail(struct list_head *n, struct list_head *head)
{
    __list_add(n, head->prev, head);
}

#define HLIST_HEAD_INIT { .first = NULL }
#define HLIST_HEAD(name) struct hlist_head name = HLIST_HEAD_INIT
#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)
#define INIT_HLIST_NODE(ptr) do { (ptr)->next = NULL; (ptr)->pprev = NULL; } while (0)
#define hlist_entry(ptr, type, member) container_of(ptr, type, member)

#endif
