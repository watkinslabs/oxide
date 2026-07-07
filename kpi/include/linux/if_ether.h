#ifndef OXIDE_LINUX_IF_ETHER_H
#define OXIDE_LINUX_IF_ETHER_H

#include <linux/types.h>

#define ETH_ALEN 6
#define ETH_TLEN 2
#define ETH_HLEN 14
#define ETH_ZLEN 60
#define ETH_DATA_LEN 1500
#define ETH_FRAME_LEN 1514
#define ETH_FCS_LEN 4

#define ETH_P_LOOP 0x0060
#define ETH_P_IP   0x0800
#define ETH_P_ARP  0x0806
#define ETH_P_IPV6 0x86DD
#define ETH_P_8021Q 0x8100
#define ETH_P_ALL  0x0003

#endif
