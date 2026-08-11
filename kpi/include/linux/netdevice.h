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

struct pcpu_sw_netstats {
    u64 rx_packets, rx_bytes, tx_packets, tx_bytes;
    unsigned char syncp[32];
} __attribute__((aligned(32)));

struct dql {
    unsigned int num_queued;
    unsigned int adj_limit;
    unsigned int last_obj_cnt;
    unsigned short stall_thrs;
    unsigned char __to_history_head[2];
    unsigned long history_head;
    unsigned long history[4];
    unsigned char __to_limit[8];
    unsigned int limit;
    unsigned int num_completed;
    unsigned int prev_ovlimit;
    unsigned int prev_num_queued;
    unsigned int prev_last_obj_cnt;
    unsigned int lowest_slack;
    unsigned long slack_start_time;
    unsigned int max_limit;
    unsigned int min_limit;
    unsigned int slack_hold_time;
    unsigned short stall_max;
    unsigned char __to_last_reap[2];
    unsigned long last_reap;
    unsigned long stall_cnt;
} __attribute__((aligned(64)));

struct netdev_queue {
    struct net_device *dev;
    void *qdisc;
    void *qdisc_sleeping;
    unsigned char kobj[64];
    const void * const *groups;
    unsigned long tx_maxrate;
    long trans_timeout;
    struct net_device *sb_dev;
    void *pool;
    struct dql dql;
    unsigned int _xmit_lock;
    int xmit_lock_owner;
    unsigned long trans_start;
    unsigned long state;
    struct napi_struct *napi;
    int numa_node;
    unsigned char __tail[28];
} __attribute__((aligned(64)));

struct netdev_hw_addr {
    struct { void *next; void *prev; } list;
    unsigned long node[3];
    unsigned char addr[MAX_ADDR_LEN];
    unsigned char type;
    _Bool global_use;
    unsigned char __to_sync_cnt[2];
    int sync_cnt;
    int refcount;
    int synced;
    unsigned long callback_head[2];
};

struct netdev_hw_addr_list {
    struct { void *next; void *prev; } list;
    int count;
    unsigned char __to_tree[4];
    void *tree;
};

struct net_device_ops {
    int (*ndo_init)(struct net_device *dev);
    void (*ndo_uninit)(struct net_device *dev);
    int (*ndo_open)(struct net_device *dev);
    int (*ndo_stop)(struct net_device *dev);
    netdev_tx_t (*ndo_start_xmit)(struct sk_buff *skb, struct net_device *dev);
    void *ndo_features_check;
    void *ndo_select_queue;
    void *ndo_change_rx_flags;
    void (*ndo_set_rx_mode)(struct net_device *dev);
    int (*ndo_set_mac_address)(struct net_device *dev, void *addr);
    void *ndo_validate_addr;
    void *ndo_do_ioctl;
    void *ndo_eth_ioctl;
    void *ndo_siocbond;
    void *ndo_siocwandev;
    void *ndo_siocdevprivate;
    int (*ndo_set_config)(struct net_device *dev, struct ifmap *map);
    int (*ndo_change_mtu)(struct net_device *dev, unsigned int mtu);
    unsigned char __tail[600];
};

struct napi_struct {
    unsigned long state;
    unsigned char __to_weight[16];
    int weight;
    unsigned char __to_poll[4];
    int (*poll)(struct napi_struct *napi, int budget);
    unsigned char __to_dev[8];
    struct net_device *dev;
    unsigned char __to_irq[360];
    int irq;
    unsigned char __tail[76];
};

struct net_device {
    unsigned char __to_netdev_ops[8];
    const struct net_device_ops *netdev_ops;
    unsigned char __to_tx[8];
    struct netdev_queue *_tx;
    unsigned char __to_real_num_tx_queues[8];
    unsigned int real_num_tx_queues;
    unsigned char __to_mtu[12];
    unsigned int mtu;
    unsigned char __to_tstats[100];
    struct pcpu_sw_netstats *tstats;
    unsigned long state;
    unsigned int flags;
    unsigned char __to_features[4];
    u64 features;
    unsigned char __to_ifindex[32];
    int ifindex;
    unsigned int real_num_rx_queues;
    unsigned char __to_name[56];
    char name[IFNAMSIZ];
    unsigned char __to_stats[248];
    struct net_device_stats {
        unsigned long rx_packets, tx_packets, rx_bytes, tx_bytes;
        unsigned long rx_errors, tx_errors, rx_dropped, tx_dropped;
        unsigned long multicast, collisions, rx_length_errors, rx_over_errors;
        unsigned long rx_crc_errors, rx_frame_errors, rx_fifo_errors, rx_missed_errors;
        unsigned long tx_aborted_errors, tx_carrier_errors, tx_fifo_errors;
        unsigned long tx_heartbeat_errors, tx_window_errors, rx_compressed, tx_compressed;
    } stats;
    unsigned char __to_ethtool_ops[16];
    const struct ethtool_ops *ethtool_ops;
    unsigned char __to_perm_addr[39];
    unsigned char perm_addr[MAX_ADDR_LEN];
    unsigned char __to_addr_len[1];
    unsigned char addr_len;
    unsigned char __to_uc[23];
    struct netdev_hw_addr_list uc;
    struct netdev_hw_addr_list mc;
    unsigned char __to_dev_addr[152];
    const unsigned char *dev_addr;
    unsigned int num_rx_queues;
    unsigned char __to_broadcast[20];
    unsigned char broadcast[MAX_ADDR_LEN];
    unsigned char __to_num_tx_queues[24];
    unsigned int num_tx_queues;
    unsigned char __to_tx_queue_len[12];
    unsigned int tx_queue_len;
    unsigned char __to_dev[284];
    struct device dev;
    unsigned char __to_tso_max_size[72];
    unsigned int tso_max_size;
    unsigned short tso_max_segs;
    unsigned char __to_phydev[48];
    struct phy_device *phydev;
    unsigned char __tail[312];
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
void dev_addr_mod(struct net_device *dev, unsigned int offset, const void *addr, size_t len);
void dev_kfree_skb_any_reason(struct sk_buff *skb, int reason);
void dev_fetch_sw_netstats(struct rtnl_link_stats64 *stats,
                           const struct pcpu_sw_netstats *tstats);
void dql_completed(struct dql *dql, unsigned int count);
void dql_reset(struct dql *dql);
int register_netdev(struct net_device *dev);
int register_netdevice(struct net_device *dev);
void unregister_netdev(struct net_device *dev);
int dev_close(struct net_device *dev);
int netif_rx(struct sk_buff *skb);
void netif_start_queue(struct net_device *dev);
void netif_stop_queue(struct net_device *dev);
void netif_wake_queue(struct net_device *dev);
void netif_tx_wake_queue(struct netdev_queue *txq);
void netif_tx_stop_all_queues(struct net_device *dev);
void netif_tx_lock(struct net_device *dev);
void netif_tx_unlock(struct net_device *dev);
void netif_carrier_on(struct net_device *dev);
void netif_carrier_off(struct net_device *dev);
void netif_device_attach(struct net_device *dev);
void netif_device_detach(struct net_device *dev);
void netif_schedule_queue(void *txq);
void synchronize_net(void);
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
    for ((ha) = (struct netdev_hw_addr *)(dev)->mc.list.next; \
         &(ha)->list != &(dev)->mc.list; (ha) = (struct netdev_hw_addr *)(ha)->list.next)
#define netdev_for_each_uc_addr(ha, dev) \
    for ((ha) = (struct netdev_hw_addr *)(dev)->uc.list.next; \
         &(ha)->list != &(dev)->uc.list; (ha) = (struct netdev_hw_addr *)(ha)->list.next)

#endif
