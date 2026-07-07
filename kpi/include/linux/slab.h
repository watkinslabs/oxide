#ifndef OXIDE_LINUX_SLAB_H
#define OXIDE_LINUX_SLAB_H

#include <linux/gfp.h>
#include <linux/types.h>

struct kmem_cache;

void *kmalloc(size_t size, gfp_t flags);
void *__kmalloc_noprof(size_t size, gfp_t flags);
void *__kmalloc_cache_noprof(struct kmem_cache *cache, gfp_t flags, size_t size);
void *__kvmalloc_node_noprof(size_t size, gfp_t flags, int node);
void *kzalloc(size_t size, gfp_t flags);
void *kcalloc(size_t n, size_t size, gfp_t flags);
void kfree(const void *ptr);
void kvfree(const void *ptr);
void kvfree_call_rcu(void *head, void *ptr);
void *kmemdup_noprof(const void *src, size_t len, gfp_t flags);
char *kstrdup(const char *s, gfp_t flags);
char *kasprintf(gfp_t flags, const char *fmt, ...);

#endif
