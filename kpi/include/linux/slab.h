#ifndef OXIDE_LINUX_SLAB_H
#define OXIDE_LINUX_SLAB_H

#include <linux/gfp.h>
#include <linux/types.h>

struct kmem_cache;
typedef unsigned int slab_flags_t;

struct kmem_cache_args {
    unsigned int align;
    unsigned int useroffset;
    unsigned int usersize;
    unsigned int freeptr_offset;
    bool use_freeptr_offset;
    void (*ctor)(void *);
};

void *kmalloc(size_t size, gfp_t flags);
void *__kmalloc_noprof(size_t size, gfp_t flags);
void *__kmalloc_cache_noprof(struct kmem_cache *cache, gfp_t flags, size_t size);
void *__kvmalloc_node_noprof(size_t size, gfp_t flags, int node);
struct kmem_cache *__kmem_cache_create_args(const char *name, unsigned int object_size, struct kmem_cache_args *args, slab_flags_t flags);
void *kmem_cache_alloc_noprof(struct kmem_cache *cache, gfp_t flags);
void kmem_cache_free(struct kmem_cache *cache, void *obj);
void kmem_cache_destroy(struct kmem_cache *cache);
void *kzalloc(size_t size, gfp_t flags);
void *kcalloc(size_t n, size_t size, gfp_t flags);
void kfree(const void *ptr);
void kvfree(const void *ptr);
void kvfree_call_rcu(void *head, void *ptr);
void *kmemdup_noprof(const void *src, size_t len, gfp_t flags);
char *kstrdup(const char *s, gfp_t flags);
char *kasprintf(gfp_t flags, const char *fmt, ...);

#endif
