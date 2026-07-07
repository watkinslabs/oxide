#ifndef OXIDE_LINUX_BITOPS_H
#define OXIDE_LINUX_BITOPS_H

#include <linux/bits.h>
#include <linux/compiler_types.h>
#include <linux/types.h>

#define BITS_PER_LONG (__SIZEOF_LONG__ * 8)
#define BIT_WORD(nr) ((nr) / BITS_PER_LONG)
#define BIT_MASK(nr) (1UL << ((nr) % BITS_PER_LONG))

static __always_inline void set_bit(unsigned long nr, volatile unsigned long *addr)
{
    addr[BIT_WORD(nr)] |= BIT_MASK(nr);
}

static __always_inline void clear_bit(unsigned long nr, volatile unsigned long *addr)
{
    addr[BIT_WORD(nr)] &= ~BIT_MASK(nr);
}

static __always_inline int test_bit(unsigned long nr, const volatile unsigned long *addr)
{
    return !!(addr[BIT_WORD(nr)] & BIT_MASK(nr));
}

unsigned long _find_first_bit(const unsigned long *addr, unsigned long size);
unsigned long _find_next_bit(const unsigned long *addr, unsigned long size, unsigned long offset);

#endif
