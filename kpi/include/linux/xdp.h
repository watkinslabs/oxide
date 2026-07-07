#ifndef OXIDE_LINUX_XDP_H
#define OXIDE_LINUX_XDP_H

#include <linux/netdevice.h>
#include <linux/types.h>

struct xdp_frame;
struct xdp_buff;
struct xdp_rxq_info;

struct xdp_frame *xdp_convert_zc_to_xdp_frame(void *xsk);
void xdp_do_flush(void);
int xdp_do_redirect(struct net_device *dev, struct xdp_buff *xdp, void *prog);
int xdp_master_redirect(struct xdp_buff *xdp, struct net_device *dev, void *prog);
void xdp_features_clear_redirect_target(struct net_device *dev);
void xdp_features_set_redirect_target(struct net_device *dev);
void xdp_return_frame(struct xdp_frame *frame);
void xdp_return_frame_rx_napi(struct xdp_frame *frame);
int xdp_rxq_info_reg_mem_model(struct xdp_rxq_info *xdp_rxq, u32 type, void *allocator);
void xdp_rxq_info_unreg(struct xdp_rxq_info *xdp_rxq);
void xdp_rxq_info_unreg_mem_model(struct xdp_rxq_info *xdp_rxq);
void xdp_set_features_flag(struct net_device *dev);
void xdp_warn(const char *msg);

#endif
