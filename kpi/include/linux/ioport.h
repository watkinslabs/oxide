#ifndef OXIDE_LINUX_IOPORT_H
#define OXIDE_LINUX_IOPORT_H

#include <linux/types.h>

#define IORESOURCE_BITS 0x000000ffULL
#define IORESOURCE_TYPE_BITS 0x00001f00ULL
#define IORESOURCE_IO 0x00000100ULL
#define IORESOURCE_MEM 0x00000200ULL
#define IORESOURCE_REG 0x00000300ULL
#define IORESOURCE_IRQ 0x00000400ULL
#define IORESOURCE_DMA 0x00000800ULL
#define IORESOURCE_BUS 0x00001000ULL
#define IORESOURCE_PREFETCH 0x00002000ULL

struct resource {
    resource_size_t start;
    resource_size_t end;
    const char *name;
    unsigned long flags;
};

static inline resource_size_t resource_size(const struct resource *res)
{
    return res == NULL || res->end < res->start ? 0 : res->end - res->start + 1;
}

static inline unsigned long resource_type(const struct resource *res)
{
    return res == NULL ? 0 : res->flags & IORESOURCE_TYPE_BITS;
}

#endif
