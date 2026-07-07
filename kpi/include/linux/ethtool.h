#ifndef OXIDE_LINUX_ETHTOOL_H
#define OXIDE_LINUX_ETHTOOL_H

#include <linux/netdevice.h>
#include <linux/types.h>

#define ETH_GSTRING_LEN 32

struct ethtool_ts_info {
    int so_timestamping;
    int phc_index;
    u32 tx_types;
    u32 rx_filters;
};

struct ethtool_eee {
    u32 supported;
    u32 advertised;
    u32 lp_advertised;
    u32 eee_active;
    u32 eee_enabled;
    u32 tx_lpi_enabled;
    u32 tx_lpi_timer;
};

struct ethtool_ops {
    u32 (*get_link)(struct net_device *dev);
    int (*get_ts_info)(struct net_device *dev, struct ethtool_ts_info *info);
};

u32 ethtool_op_get_link(struct net_device *dev);
int ethtool_op_get_ts_info(struct net_device *dev, struct ethtool_ts_info *info);
int ethtool_virtdev_set_link_ksettings(struct net_device *dev, const void *cmd,
                                        u32 speed, u8 duplex);
void ethtool_convert_legacy_u32_to_link_mode(unsigned long *dst, u32 legacy);
bool ethtool_convert_link_mode_to_legacy_u32(u32 *dst, const unsigned long *src);
void ethtool_puts(u8 **data, const char *str);
void ethtool_sprintf(u8 **data, const char *fmt, ...);

#endif
