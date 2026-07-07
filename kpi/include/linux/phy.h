#ifndef OXIDE_LINUX_PHY_H
#define OXIDE_LINUX_PHY_H

#include <linux/ethtool.h>
#include <linux/netdevice.h>
#include <linux/types.h>

#define SPEED_10 10
#define SPEED_100 100
#define SPEED_1000 1000
#define DUPLEX_HALF 0
#define DUPLEX_FULL 1
#define AUTONEG_DISABLE 0
#define AUTONEG_ENABLE 1

struct ifreq;

struct phy_device {
    struct net_device *attached_dev;
    int speed;
    int duplex;
    u8 link;
    u8 autoneg;
    u8 pause;
    u8 asym_pause;
    u32 interface;
    int irq;
    int page;
    u16 regs[32];
    u16 mmd_regs[8][32];
    void (*phy_link_change)(struct net_device *dev);
};

int phy_connect_direct(struct net_device *dev, struct phy_device *phydev,
                       void (*handler)(struct net_device *), u32 interface);
void phy_disconnect(struct phy_device *phydev);
void phy_start(struct phy_device *phydev);
void phy_stop(struct phy_device *phydev);
int phy_suspend(struct phy_device *phydev);
int phy_resume(struct phy_device *phydev);
int phy_start_aneg(struct phy_device *phydev);
int phy_init_hw(struct phy_device *phydev);
int genphy_soft_reset(struct phy_device *phydev);
void phy_print_status(struct phy_device *phydev);
void phy_attached_info(struct phy_device *phydev);
void phy_mac_interrupt(struct phy_device *phydev);
int phy_do_ioctl_running(struct net_device *dev, struct ifreq *ifr, int cmd);
void phy_get_pause(struct phy_device *phydev, bool *tx_pause, bool *rx_pause);
void phy_set_asym_pause(struct phy_device *phydev, bool rx, bool tx);
void phy_support_asym_pause(struct phy_device *phydev);
int phy_support_eee(struct phy_device *phydev);
int phy_ethtool_get_eee(struct phy_device *phydev, struct ethtool_eee *data);
int phy_ethtool_set_eee(struct phy_device *phydev, struct ethtool_eee *data);
int phy_ethtool_get_link_ksettings(struct phy_device *phydev, void *cmd);
int phy_ethtool_set_link_ksettings(struct phy_device *phydev, const void *cmd);
int phy_ethtool_nway_reset(struct phy_device *phydev);
int phy_set_max_speed(struct phy_device *phydev, u32 max_speed);
int phy_speed_down(struct phy_device *phydev, bool sync);
int phy_speed_up(struct phy_device *phydev);
int phy_modify(struct phy_device *phydev, u32 regnum, u16 mask, u16 set);
int __phy_modify(struct phy_device *phydev, u32 regnum, u16 mask, u16 set);
int phy_select_page(struct phy_device *phydev, int page);
int phy_restore_page(struct phy_device *phydev, int oldpage, int ret);
int phy_read_paged(struct phy_device *phydev, int page, u32 regnum);
int phy_write_paged(struct phy_device *phydev, int page, u32 regnum, u16 val);
int phy_modify_paged(struct phy_device *phydev, int page, u32 regnum, u16 mask, u16 set);
int phy_write_mmd(struct phy_device *phydev, int devad, u32 regnum, u16 val);
int __phy_write_mmd(struct phy_device *phydev, int devad, u32 regnum, u16 val);
int __phy_modify_mmd(struct phy_device *phydev, int devad, u32 regnum, u16 mask, u16 set);
struct phy_device *mdiobus_get_phy(void *bus, int addr);
int mdiobus_read(void *bus, int addr, u32 regnum);
int mdiobus_write(void *bus, int addr, u32 regnum, u16 val);

#endif
