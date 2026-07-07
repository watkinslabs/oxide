#ifndef OXIDE_LINUX_NETDEVICE_H
#define OXIDE_LINUX_NETDEVICE_H

#include <linux/device.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/skbuff.h>
#include <linux/types.h>

#define NET_NAME_UNKNOWN 0
#define NETDEV_TX_OK 0
#define NETDEV_TX_BUSY 1

struct rtnl_link_stats64 {
    u64 rx_packets;
    u64 tx_packets;
    u64 rx_bytes;
    u64 tx_bytes;
    u64 rx_errors;
    u64 tx_errors;
    u64 rx_dropped;
    u64 tx_dropped;
};

struct net_device_ops {
    int (*ndo_open)(struct net_device *dev);
    int (*ndo_stop)(struct net_device *dev);
    netdev_tx_t (*ndo_start_xmit)(struct sk_buff *skb, struct net_device *dev);
};

struct net_device {
    struct device dev;
    char name[IFNAMSIZ];
    const struct net_device_ops *netdev_ops;
    unsigned int mtu;
    unsigned int flags;
    void *priv;
    unsigned char dev_addr[ETH_ALEN];
    unsigned char addr_len;
    unsigned int ifindex;
    unsigned int state;
    struct rtnl_link_stats64 stats;
};

struct net_device *alloc_netdev_mqs(int sizeof_priv, const char *name,
                                    unsigned char name_assign_type,
                                    void (*setup)(struct net_device *),
                                    unsigned int txqs, unsigned int rxqs);
struct net_device *alloc_netdev(int sizeof_priv, const char *name,
                                unsigned char name_assign_type,
                                void (*setup)(struct net_device *));
struct net_device *alloc_etherdev_mqs(int sizeof_priv, unsigned int txqs, unsigned int rxqs);
struct net_device *alloc_etherdev(int sizeof_priv);
void free_netdev(struct net_device *dev);
void *netdev_priv(const struct net_device *dev);
int register_netdev(struct net_device *dev);
void unregister_netdev(struct net_device *dev);
int netif_rx(struct sk_buff *skb);
void netif_start_queue(struct net_device *dev);
void netif_stop_queue(struct net_device *dev);
void netif_wake_queue(struct net_device *dev);
void netif_carrier_on(struct net_device *dev);
void netif_carrier_off(struct net_device *dev);

#define netdev_for_each_tx_queue(dev, fn, arg) do { (void)(dev); (void)(arg); } while (0)

#endif
