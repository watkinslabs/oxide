#ifndef OXIDE_LINUX_XARRAY_H
#define OXIDE_LINUX_XARRAY_H

#include <linux/types.h>
#include <linux/spinlock.h>

struct xarray { spinlock_t xa_lock; gfp_t xa_flags; void *xa_head; };
#define XARRAY_INIT(name, flags) { .xa_lock = { 0 }, .xa_flags = (flags), .xa_head = NULL }
#define DEFINE_XARRAY(name) struct xarray name = XARRAY_INIT(name, 0)
#define XA_PRESENT 8U

void xa_init_flags(struct xarray *xa, gfp_t flags);
void *xa_load(struct xarray *xa, unsigned long index);
int xa_insert(struct xarray *xa, unsigned long index, void *entry, gfp_t gfp);
void *xa_store(struct xarray *xa, unsigned long index, void *entry, gfp_t gfp);
void *xa_erase(struct xarray *xa, unsigned long index);
void *xa_find(struct xarray *xa, unsigned long *index, unsigned long max, unsigned int filter);
void *xa_find_after(struct xarray *xa, unsigned long *index, unsigned long max, unsigned int filter);
void xa_destroy(struct xarray *xa);

#endif
