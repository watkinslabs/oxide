#ifndef OXIDE_LINUX_VMALLOC_H
#define OXIDE_LINUX_VMALLOC_H

#include <linux/types.h>

void *vmalloc(unsigned long size);
void vfree(const void *addr);

#endif
