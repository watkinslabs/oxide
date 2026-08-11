/*
 * Stable layout contract for C modules built against kpi/include.
 * The Rust mirrors carry the same constants in linux_pci/core/tests.rs;
 * changing either side requires deliberately updating both contracts.
 */
#include <linux/pci.h>

_Static_assert(sizeof(struct kobject) == 112, "kobject ABI");
_Static_assert(_Alignof(struct kobject) == 8, "kobject alignment");
_Static_assert(sizeof(struct dev_pm_info) == 40, "dev_pm_info ABI");
_Static_assert(sizeof(struct device) == 304, "device ABI");
_Static_assert(offsetof(struct device, dma_mask) == 0, "device dma_mask offset");
_Static_assert(offsetof(struct device, kobj) == 128, "device kobj offset");
_Static_assert(offsetof(struct device, power) == 264, "device power offset");
_Static_assert(sizeof(struct device_driver) == 64, "device_driver ABI");
_Static_assert(sizeof(struct resource) == 32, "resource ABI");
_Static_assert(sizeof(struct pci_dev) == 1080, "pci_dev ABI");
_Static_assert(offsetof(struct pci_dev, vendor) == 304, "pci_dev vendor offset");
_Static_assert(offsetof(struct pci_dev, resource) == 328, "pci_dev resource offset");
_Static_assert(offsetof(struct pci_dev, config_space) == 528, "pci_dev config offset");
_Static_assert(offsetof(struct pci_dev, saved_config_space) == 812, "pci_dev saved config offset");
_Static_assert(offsetof(struct pci_dev, current_state) == 1068, "pci_dev power offset");
_Static_assert(sizeof(struct pci_driver) == 96, "pci_driver ABI");
_Static_assert(offsetof(struct pci_driver, driver) == 32, "pci_driver device_driver offset");

int main(void) { return 0; }
