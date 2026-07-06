#ifndef OXIDE_LINUX_XARRAY_H
#define OXIDE_LINUX_XARRAY_H

#include <linux/types.h>

struct xarray { void *xa_head; };
#define XARRAY_INIT(name, flags) { .xa_head = NULL }
#define DEFINE_XARRAY(name) struct xarray name = XARRAY_INIT(name, 0)

void xa_init_flags(struct xarray *xa, unsigned int flags);
void *xa_load(struct xarray *xa, unsigned long index);
int xa_insert(struct xarray *xa, unsigned long index, void *entry, gfp_t gfp);
void *xa_erase(struct xarray *xa, unsigned long index);

#endif
