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
    unsigned char cb[OXIDE_SKB_CB_LEN];
    void *owner;
};

struct sk_buff *alloc_skb(unsigned int size, gfp_t priority);
struct sk_buff *__alloc_skb(unsigned int size, gfp_t priority, int flags, int node);
struct sk_buff *dev_alloc_skb(unsigned int length);
void kfree_skb(struct sk_buff *skb);
void dev_kfree_skb(struct sk_buff *skb);
unsigned char *skb_put(struct sk_buff *skb, unsigned int len);
unsigned char *skb_push(struct sk_buff *skb, unsigned int len);
unsigned char *skb_pull(struct sk_buff *skb, unsigned int len);
void skb_reserve(struct sk_buff *skb, unsigned int len);
unsigned char *skb_tail_pointer(const struct sk_buff *skb);
__be16 eth_type_trans(struct sk_buff *skb, struct net_device *dev);

#endif
