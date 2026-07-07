#ifndef OXIDE_LINUX_ETHERDEVICE_H
#define OXIDE_LINUX_ETHERDEVICE_H

#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/types.h>

void ether_setup(struct net_device *dev);
void eth_hw_addr_set(struct net_device *dev, const u8 *addr);

#endif
