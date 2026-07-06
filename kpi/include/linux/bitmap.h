#ifndef OXIDE_LINUX_BITMAP_H
#define OXIDE_LINUX_BITMAP_H

#include <linux/bitops.h>

#define DECLARE_BITMAP(name, bits) unsigned long name[((bits) + BITS_PER_LONG - 1) / BITS_PER_LONG]

static __always_inline void bitmap_zero(unsigned long *dst, unsigned int nbits)
{
    unsigned int words = (nbits + BITS_PER_LONG - 1) / BITS_PER_LONG;
    for (unsigned int i = 0; i < words; i++) dst[i] = 0;
}

static __always_inline void bitmap_fill(unsigned long *dst, unsigned int nbits)
{
    unsigned int words = (nbits + BITS_PER_LONG - 1) / BITS_PER_LONG;
    for (unsigned int i = 0; i < words; i++) dst[i] = ~0UL;
}

#endif
