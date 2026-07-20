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
#define NAPI_POLL_WEIGHT 64
#define MAX_ADDR_LEN 32

struct ethtool_ops;
struct phy_device;

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

struct netdev_hw_addr {
    struct netdev_hw_addr *next;
    unsigned char addr[MAX_ADDR_LEN];
};

struct netdev_hw_addr_list {
    struct netdev_hw_addr *head;
    unsigned int count;
};

struct net_device_ops {
    int (*ndo_open)(struct net_device *dev);
    int (*ndo_stop)(struct net_device *dev);
    netdev_tx_t (*ndo_start_xmit)(struct sk_buff *skb, struct net_device *dev);
    void (*ndo_set_rx_mode)(struct net_device *dev);
    int (*ndo_change_mtu)(struct net_device *dev, unsigned int mtu);
    int (*ndo_set_mac_address)(struct net_device *dev, void *addr);
    int (*ndo_set_config)(struct net_device *dev, struct ifmap *map);
};

struct napi_struct {
    struct net_device *dev;
    int (*poll)(struct napi_struct *napi, int budget);
    int weight;
    unsigned int state;
    unsigned int rxq;
    unsigned int txq;
    unsigned int scheduled;
    u64 oxide_ingress_generation;
};

struct net_device {
    struct device dev;
    char name[IFNAMSIZ];
    const struct net_device_ops *netdev_ops;
    unsigned int mtu;
    unsigned int tx_queue_len;
    unsigned int flags;
    void *priv;
    unsigned char dev_addr[ETH_ALEN];
    unsigned char broadcast[MAX_ADDR_LEN];
    unsigned char addr_len;
    unsigned int ifindex;
    unsigned int state;
    struct rtnl_link_stats64 stats;
    const struct ethtool_ops *ethtool_ops;
    struct phy_device *phydev;
    unsigned int num_tx_queues;
    unsigned int real_num_tx_queues;
    unsigned int real_num_rx_queues;
    unsigned int tso_max_size;
    unsigned short tso_max_segs;
    struct netdev_hw_addr_list uc;
    struct netdev_hw_addr_list mc;
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
int register_netdevice(struct net_device *dev);
void unregister_netdev(struct net_device *dev);
int dev_close(struct net_device *dev);
int netif_rx(struct sk_buff *skb);
void netif_start_queue(struct net_device *dev);
void netif_stop_queue(struct net_device *dev);
void netif_wake_queue(struct net_device *dev);
void netif_tx_wake_queue(struct net_device *dev);
void netif_tx_stop_all_queues(struct net_device *dev);
void netif_tx_lock(struct net_device *dev);
void netif_tx_unlock(struct net_device *dev);
void netif_carrier_on(struct net_device *dev);
void netif_carrier_off(struct net_device *dev);
void netif_device_attach(struct net_device *dev);
void netif_device_detach(struct net_device *dev);
void netif_schedule_queue(void *txq);
void netdev_notify_peers(struct net_device *dev);
void netdev_update_features(struct net_device *dev);
void netdev_sw_irq_coalesce_default_on(struct net_device *dev);
int netif_set_real_num_tx_queues(struct net_device *dev, unsigned int txq);
int netif_set_real_num_rx_queues(struct net_device *dev, unsigned int rxq);
void netif_set_tso_max_size(struct net_device *dev, unsigned int size);
void netif_set_tso_max_segs(struct net_device *dev, unsigned short segs);
int __netif_set_xps_queue(struct net_device *dev, const void *mask, unsigned short index);
int netif_enable_cpu_rmap(struct net_device *dev, unsigned short queues);
void netif_napi_add_weight_locked(struct net_device *dev, struct napi_struct *napi,
                                  int (*poll)(struct napi_struct *, int),
                                  int weight);
void __netif_napi_del_locked(struct napi_struct *napi);
void napi_enable(struct napi_struct *napi);
void napi_disable(struct napi_struct *napi);
void __napi_schedule(struct napi_struct *napi);
void __napi_schedule_irqoff(struct napi_struct *napi);
bool napi_schedule_prep(struct napi_struct *napi);
bool napi_complete_done(struct napi_struct *napi, int work_done);
struct sk_buff *napi_alloc_skb(struct napi_struct *napi, unsigned int len);
struct sk_buff *napi_build_skb(void *data, unsigned int frag_size);
void napi_consume_skb(struct sk_buff *skb, int budget);
struct sk_buff *napi_get_frags(struct napi_struct *napi);
int napi_gro_frags(struct napi_struct *napi);
int gro_receive_skb(struct napi_struct *napi, struct sk_buff *skb);
void *__napi_alloc_frag_align(unsigned int fragsz, unsigned int align_mask);
bool skb_page_frag_refill(unsigned int sz, void *page_frag, gfp_t gfp);
void netif_queue_set_napi(struct net_device *dev, unsigned short queue,
                          struct napi_struct *napi);
void netif_napi_set_irq_locked(struct napi_struct *napi, int irq);
void netdev_stats_to_stats64(struct rtnl_link_stats64 *stats,
                             const struct net_device *dev);
void netdev_stat_queue_sum(const struct net_device *dev,
                           struct rtnl_link_stats64 *stats);
void netdev_rss_key_fill(void *buffer, size_t len);
void net_dim_work_cancel(void *dim);
void netdev_printk(const char *level, const struct net_device *dev,
                   const char *fmt, ...);
void netdev_err(const struct net_device *dev, const char *fmt, ...);
void netdev_warn(const struct net_device *dev, const char *fmt, ...);
void netdev_notice(const struct net_device *dev, const char *fmt, ...);
void netdev_info(const struct net_device *dev, const char *fmt, ...);
void rtnl_lock(void);
void rtnl_unlock(void);

#define netdev_for_each_tx_queue(dev, fn, arg) do { (void)(dev); (void)(arg); } while (0)
#define netdev_mc_count(dev) ((dev)->mc.count)
#define netdev_uc_count(dev) ((dev)->uc.count)
#define netdev_for_each_mc_addr(ha, dev) \
    for ((ha) = (dev)->mc.head; (ha) != NULL; (ha) = (ha)->next)
#define netdev_for_each_uc_addr(ha, dev) \
    for ((ha) = (dev)->uc.head; (ha) != NULL; (ha) = (ha)->next)

#endif
