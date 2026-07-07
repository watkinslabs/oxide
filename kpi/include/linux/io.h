#ifndef OXIDE_LINUX_IO_H
#define OXIDE_LINUX_IO_H

#include <linux/compiler_types.h>
#include <linux/types.h>

typedef u64 phys_addr_t;
typedef u64 resource_size_t;

void __iomem *ioremap(phys_addr_t phys, unsigned long size);
void __iomem *ioremap_nocache(phys_addr_t phys, unsigned long size);
void iounmap(void __iomem *addr);

u8 readb(const volatile void __iomem *addr);
u16 readw(const volatile void __iomem *addr);
u32 readl(const volatile void __iomem *addr);
u64 readq(const volatile void __iomem *addr);
void writeb(u8 value, volatile void __iomem *addr);
void writew(u16 value, volatile void __iomem *addr);
void writel(u32 value, volatile void __iomem *addr);
void writeq(u64 value, volatile void __iomem *addr);

void memcpy_toio(volatile void __iomem *dst, const void *src, unsigned long count);
void memcpy_fromio(void *dst, const volatile void __iomem *src, unsigned long count);
void memset_io(volatile void __iomem *dst, int value, unsigned long count);

u8 inb(u16 port);
u16 inw(u16 port);
u32 inl(u16 port);
void outb(u8 value, u16 port);
void outw(u16 value, u16 port);
void outl(u32 value, u16 port);

void mb(void);
void rmb(void);
void wmb(void);
void mmiowb(void);

#endif
