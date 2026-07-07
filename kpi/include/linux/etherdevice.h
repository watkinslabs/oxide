#ifndef OXIDE_LINUX_ETHERDEVICE_H
#define OXIDE_LINUX_ETHERDEVICE_H

#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/types.h>

void ether_setup(struct net_device *dev);
void eth_hw_addr_set(struct net_device *dev, const u8 *addr);
int eth_validate_addr(struct net_device *dev);
int eth_mac_addr(struct net_device *dev, void *p);
int eth_prepare_mac_addr_change(struct net_device *dev, void *p);
void eth_commit_mac_addr_change(struct net_device *dev, void *p);
int eth_platform_get_mac_address(void *dev, u8 *addr);

#endif
