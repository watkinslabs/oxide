#ifndef OXIDE_LINUX_BITS_H
#define OXIDE_LINUX_BITS_H

#define BIT(nr) (1UL << (nr))
#define BIT_ULL(nr) (1ULL << (nr))
#define GENMASK(h, l) (((~0UL) - (1UL << (l)) + 1) & (~0UL >> (__SIZEOF_LONG__ * 8 - 1 - (h))))

#endif
