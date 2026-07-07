#ifndef OXIDE_LINUX_VMALLOC_H
#define OXIDE_LINUX_VMALLOC_H

#include <linux/types.h>

#define VM_MAP 0x00000004UL
#define PAGE_KERNEL ((pgprot_t)0)

typedef unsigned long pgprot_t;

void *vmalloc(unsigned long size);
void *vzalloc_noprof(unsigned long size);
void *vmap(struct page **pages, unsigned int count, unsigned long flags, pgprot_t prot);
void vunmap(const void *addr);
void vfree(const void *addr);

#endif
