#ifndef OXIDE_LINUX_PHY_H
#define OXIDE_LINUX_PHY_H

#include <linux/ethtool.h>
#include <linux/device.h>
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

#define PHY_MAX_ADDR 32
#define MII_BUS_ID_SIZE 20
struct mii_bus;
struct mdio_bus_stats { u8 _opaque[32]; };

struct mdio_device {
    struct device dev;
    struct mii_bus *bus;
    char modalias[32];
    void *bus_match;
    void *device_free;
    void *device_remove;
    int addr;
    u32 flags;
    u32 reset_state;
    void *reset_gpio;
    void *reset_ctrl;
    u32 reset_assert_delay;
    u32 reset_deassert_delay;
};

struct phy_device {
    struct mdio_device mdio;
    u8 _to_flags[160];
    u8 _flags[4];
    u8 _to_interface[12];
    u32 interface;
    u8 _to_speed[12];
    int speed;
    int duplex;
    u8 _to_irq[192];
    int irq;
    u8 _to_attached_dev[188];
    struct net_device *attached_dev;
    u8 _to_phy_link_change[32];
    void (*phy_link_change)(struct net_device *dev);
    u8 _tail[32];
};

struct mii_bus {
    void *owner;
    const char *name;
    char id[MII_BUS_ID_SIZE];
    u8 _id_pad[44];
    void *priv;
    int (*read)(struct mii_bus *bus, int addr, int regnum);
    int (*write)(struct mii_bus *bus, int addr, int regnum, u16 val);
    int (*read_c45)(struct mii_bus *bus, int addr, int devnum, int regnum);
    int (*write_c45)(struct mii_bus *bus, int addr, int devnum, int regnum, u16 val);
    int (*reset)(struct mii_bus *bus);
    struct mdio_bus_stats stats[PHY_MAX_ADDR];
    u8 _mdio_lock[32];
    struct device *parent;
    u32 state;
    u8 _state_pad[4];
    struct device dev;
    struct phy_device *mdio_map[PHY_MAX_ADDR];
    u32 phy_mask;
    u32 phy_ignore_ta_mask;
    int irq[PHY_MAX_ADDR];
    int reset_delay_us;
    int reset_post_delay_us;
    void *reset_gpiod;
    u8 _shared_lock[32];
    void *shared[PHY_MAX_ADDR];
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
struct phy_device *mdiobus_get_phy(struct mii_bus *bus, int addr);
int mdiobus_read(struct mii_bus *bus, int addr, u32 regnum);
int mdiobus_write(struct mii_bus *bus, int addr, u32 regnum, u16 val);
int __mdiobus_write(struct mii_bus *bus, int addr, u32 regnum, u16 val);
struct mii_bus *devm_mdiobus_alloc_size(struct device *dev, int sizeof_priv);
int __devm_mdiobus_register(struct device *dev, struct mii_bus *bus, void *owner);

#endif
