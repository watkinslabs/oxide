/*
 * Stable layout contract for C modules built against kpi/include.
 * The Rust mirrors carry the same constants in linux_pci/core/tests.rs;
 * changing either side requires deliberately updating both contracts.
 */
#include <linux/pci.h>
#include <linux/skbuff.h>
#include <linux/phy.h>
#include <linux/input.h>

_Static_assert(sizeof(struct kobject) == 64, "kobject ABI");
_Static_assert(_Alignof(struct kobject) == 8, "kobject alignment");
_Static_assert(sizeof(struct dev_pm_info) == 320, "dev_pm_info ABI");
_Static_assert(sizeof(struct device) == 776, "device ABI");
_Static_assert(offsetof(struct device, kobj) == 0, "device kobj offset");
_Static_assert(offsetof(struct device, dma_mask) == 600, "device dma_mask offset");
_Static_assert(offsetof(struct device, power) == 232, "device power offset");
_Static_assert(sizeof(struct device_driver) == 152, "device_driver ABI");
_Static_assert(sizeof(struct net_device) == 2688, "net_device ABI");
_Static_assert(offsetof(struct net_device, netdev_ops) == 8, "netdev_ops offset");
_Static_assert(offsetof(struct net_device, ifindex) == 224, "netdev ifindex offset");
_Static_assert(offsetof(struct net_device, tstats) == 160, "netdev tstats offset");
_Static_assert(offsetof(struct net_device, name) == 288, "netdev name offset");
_Static_assert(offsetof(struct net_device, dev) == 1464, "netdev device offset");
_Static_assert(offsetof(struct net_device, phydev) == 2368, "netdev phydev offset");
_Static_assert(sizeof(struct dql) == 128, "dql ABI");
_Static_assert(offsetof(struct dql, limit) == 64, "dql limit offset");
_Static_assert(sizeof(struct netdev_queue) == 320, "netdev_queue ABI");
_Static_assert(_Alignof(struct netdev_queue) == 64, "netdev_queue alignment");
_Static_assert(offsetof(struct netdev_queue, dql) == 128, "netdev_queue dql offset");
_Static_assert(offsetof(struct netdev_queue, state) == 272, "netdev_queue state offset");
_Static_assert(sizeof(struct netdev_hw_addr) == 104, "netdev_hw_addr ABI");
_Static_assert(offsetof(struct netdev_hw_addr, addr) == 40, "netdev_hw_addr address offset");
_Static_assert(sizeof(struct netdev_hw_addr_list) == 32, "netdev_hw_addr_list ABI");
_Static_assert(offsetof(struct netdev_hw_addr_list, tree) == 24, "netdev_hw_addr_list tree offset");
_Static_assert(sizeof(struct napi_struct) == 496, "napi ABI");
_Static_assert(offsetof(struct napi_struct, state) == 0, "napi state offset");
_Static_assert(offsetof(struct napi_struct, poll) == 32, "napi poll offset");
_Static_assert(offsetof(struct napi_struct, dev) == 48, "napi dev offset");
_Static_assert(sizeof(struct resource) == 64, "resource ABI");
_Static_assert(sizeof(struct pci_dev) == 2736, "pci_dev ABI");
_Static_assert(offsetof(struct pci_dev, vendor) == 60, "pci_dev vendor offset");
_Static_assert(offsetof(struct pci_dev, current_state) == 160, "pci_dev power offset");
_Static_assert(offsetof(struct pci_dev, dev) == 200, "pci_dev device offset");
_Static_assert(offsetof(struct pci_dev, resource) == 984, "pci_dev resource offset");
_Static_assert(offsetof(struct pci_dev, saved_config_space) == 2152, "pci_dev saved config offset");
_Static_assert(sizeof(struct pci_driver) == 288, "pci_driver ABI");
_Static_assert(offsetof(struct pci_driver, driver) == 104, "pci_driver device_driver offset");
_Static_assert(sizeof(struct sk_buff) == 232, "sk_buff ABI");
_Static_assert(_Alignof(struct sk_buff) == 8, "sk_buff alignment");
_Static_assert(offsetof(struct sk_buff, next) == 0, "sk_buff next offset");
_Static_assert(offsetof(struct sk_buff, len) == 112, "sk_buff len offset");
_Static_assert(offsetof(struct sk_buff, headers) == 128, "sk_buff headers offset");
_Static_assert(offsetof(struct sk_buff, protocol) == 176, "sk_buff protocol offset");
_Static_assert(offsetof(struct sk_buff, tail) == 188, "sk_buff tail offset");
_Static_assert(offsetof(struct sk_buff, head) == 200, "sk_buff head offset");
_Static_assert(offsetof(struct sk_buff, extensions) == 224, "sk_buff extensions offset");
_Static_assert(sizeof(struct mii_bus) == 2672, "mii_bus ABI");
_Static_assert(offsetof(struct mii_bus, priv) == 80, "mii_bus priv offset");
_Static_assert(offsetof(struct mii_bus, read) == 88, "mii_bus read offset");
_Static_assert(offsetof(struct mii_bus, mdio_map) == 1976, "mii_bus address map offset");
_Static_assert(sizeof(struct mdio_device) == 880, "mdio_device ABI");
_Static_assert(offsetof(struct mdio_device, bus) == 776, "mdio_device bus offset");
_Static_assert(offsetof(struct mdio_device, addr) == 840, "mdio_device address offset");
_Static_assert(sizeof(struct phy_device) == 1544, "phy_device ABI");
_Static_assert(offsetof(struct phy_device, mdio) == 0, "phy_device mdio offset");
_Static_assert(offsetof(struct phy_device, speed) == 1072, "phy_device speed offset");
_Static_assert(offsetof(struct phy_device, attached_dev) == 1464, "phy_device attached offset");
_Static_assert(sizeof(struct input_dev) == 1408, "input_dev ABI");
_Static_assert(offsetof(struct input_dev, propbit) == 32, "input_dev propbit offset");
_Static_assert(offsetof(struct input_dev, absinfo) == 328, "input_dev absinfo offset");
_Static_assert(offsetof(struct input_dev, dev) == 544, "input_dev device offset");

int main(void) { return 0; }
