#ifndef OXIDE_LINUX_SLAB_H
#define OXIDE_LINUX_SLAB_H

#include <linux/gfp.h>
#include <linux/types.h>

void *kmalloc(size_t size, gfp_t flags);
void *kzalloc(size_t size, gfp_t flags);
void *kcalloc(size_t n, size_t size, gfp_t flags);
void kfree(const void *ptr);
char *kstrdup(const char *s, gfp_t flags);
char *kasprintf(gfp_t flags, const char *fmt, ...);

#endif
