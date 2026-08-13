#ifndef OXIDE_LINUX_IDR_H
#define OXIDE_LINUX_IDR_H

#include <linux/types.h>
#include <linux/xarray.h>

struct idr { struct xarray idr_rt; };
struct ida { struct xarray xa; };

#define IDR_INIT(name) { .idr_rt = XARRAY_INIT(name, 0) }
#define DEFINE_IDR(name) struct idr name = IDR_INIT(name)
#define IDA_INIT(name) { .xa = XARRAY_INIT(name, 5) }
#define DEFINE_IDA(name) struct ida name = IDA_INIT(name)

void idr_init(struct idr *idr);
int idr_alloc(struct idr *idr, void *ptr, int start, int end, gfp_t gfp);
void *idr_remove(struct idr *idr, unsigned long id);
void ida_init(struct ida *ida);
int ida_alloc_range(struct ida *ida, unsigned int min, unsigned int max, gfp_t gfp);
void ida_free(struct ida *ida, unsigned int id);
void ida_destroy(struct ida *ida);

#endif
