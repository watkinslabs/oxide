#ifndef OXIDE_LINUX_IF_H
#define OXIDE_LINUX_IF_H

#include <linux/types.h>

#define IFNAMSIZ 16

#define IFF_UP        0x0001
#define IFF_BROADCAST 0x0002
#define IFF_DEBUG     0x0004
#define IFF_LOOPBACK  0x0008
#define IFF_POINTOPOINT 0x0010
#define IFF_NOTRAILERS 0x0020
#define IFF_RUNNING   0x0040
#define IFF_NOARP     0x0080
#define IFF_PROMISC   0x0100
#define IFF_ALLMULTI  0x0200
#define IFF_MASTER    0x0400
#define IFF_SLAVE     0x0800
#define IFF_MULTICAST 0x1000

struct ifmap {
    unsigned long mem_start;
    unsigned long mem_end;
    unsigned short base_addr;
    unsigned char irq;
    unsigned char dma;
    unsigned char port;
};

#endif
