#ifndef OXIDE_LINUX_SKBUFF_H
#define OXIDE_LINUX_SKBUFF_H

#include <linux/gfp.h>
#include <linux/if_ether.h>
#include <linux/types.h>

#define NET_RX_SUCCESS 0
#define NET_RX_DROP 1
#define OXIDE_SKB_CB_LEN 48

struct net_device;

struct sk_buff {
    unsigned char *head;
    unsigned char *data;
    unsigned char *tail;
    unsigned char *end;
    u32 len;
    u16 protocol;
    struct net_device *dev;
    u8 ip_summed;
    u16 csum_start;
    u16 csum_offset;
    u8 nr_frags;
    unsigned char cb[OXIDE_SKB_CB_LEN];
    void *owner;
};

struct sk_buff *alloc_skb(unsigned int size, gfp_t priority);
struct sk_buff *__alloc_skb(unsigned int size, gfp_t priority, int flags, int node);
struct sk_buff *dev_alloc_skb(unsigned int length);
void kfree_skb(struct sk_buff *skb);
void consume_skb(struct sk_buff *skb);
void dev_kfree_skb(struct sk_buff *skb);
unsigned char *skb_put(struct sk_buff *skb, unsigned int len);
unsigned char *skb_push(struct sk_buff *skb, unsigned int len);
unsigned char *skb_pull(struct sk_buff *skb, unsigned int len);
void skb_reserve(struct sk_buff *skb, unsigned int len);
unsigned char *skb_tail_pointer(const struct sk_buff *skb);
__be16 eth_type_trans(struct sk_buff *skb, struct net_device *dev);
void skb_trim(struct sk_buff *skb, unsigned int len);
int ___pskb_trim(struct sk_buff *skb, unsigned int len);
unsigned char *__pskb_pull_tail(struct sk_buff *skb, unsigned int delta);
int pskb_expand_head(struct sk_buff *skb, int nhead, int ntail, gfp_t gfp);
int __skb_pad(struct sk_buff *skb, unsigned int pad, bool free_on_error);
int skb_copy_bits(const struct sk_buff *skb, int offset, void *to, int len);
bool skb_partial_csum_set(struct sk_buff *skb, u16 start, u16 off);
void skb_tstamp_tx(struct sk_buff *skb, const void *hwtstamps);
void skb_clone_tx_timestamp(struct sk_buff *skb);
void sk_skb_reason_drop(struct sk_buff *skb, unsigned int reason);
void skb_add_rx_frag_netmem(struct sk_buff *skb, int i, void *netmem,
                            int off, int size, unsigned int truesize);
void skb_coalesce_rx_frag(struct sk_buff *skb, int i, unsigned int size,
                          unsigned int truesize);
int skb_to_sgvec(const struct sk_buff *skb, void *sg, int offset, int len);
bool __skb_flow_dissect(void);
struct sk_buff *build_skb(void *data, unsigned int frag_size);

#endif
