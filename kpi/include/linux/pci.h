#ifndef OXIDE_LINUX_PCI_H
#define OXIDE_LINUX_PCI_H

#include <linux/device.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/pm.h>
#include <linux/types.h>

#define PCI_STD_NUM_BARS 6
#define DEVICE_COUNT_RESOURCE PCI_STD_NUM_BARS
#define PCI_CONFIG_DWORDS 64
#define PCI_NAME_LEN 13
#define PCI_DEVFN_SLOT_SHIFT 3
#define PCI_SLOT_MASK 0x1f
#define PCI_FUNC_MASK 0x07
#define PCI_ANY_ID 0xffffffffU
#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "oxide"
#endif

#define PCI_IRQ_LEGACY 0x00000001U
#define PCI_IRQ_MSI 0x00000002U
#define PCI_IRQ_MSIX 0x00000004U

typedef int pci_power_t;
#define PCI_D0 0
#define PCI_D1 1
#define PCI_D2 2
#define PCI_D3hot 3
#define PCI_D3cold 4
#define PCI_POWER_ERROR (-1)

#define PCI_DEVFN(slot, func) ((((slot) & PCI_SLOT_MASK) << PCI_DEVFN_SLOT_SHIFT) | ((func) & PCI_FUNC_MASK))
#define PCI_SLOT(devfn) (((devfn) >> PCI_DEVFN_SLOT_SHIFT) & PCI_SLOT_MASK)
#define PCI_FUNC(devfn) ((devfn) & PCI_FUNC_MASK)

#define PCI_DEVICE(vend, dev) \
    .vendor = (vend), .device = (dev), .subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID

struct pci_dev {
    struct device dev;
    u16 vendor;
    u16 device;
    u16 subsystem_vendor;
    u16 subsystem_device;
    u32 class;
    u8 bus;
    u8 devfn;
    unsigned int irq;
    struct resource resource[DEVICE_COUNT_RESOURCE];
    void *driver_data;
    u32 config_space[PCI_CONFIG_DWORDS];
    unsigned int irq_vector_base;
    int irq_vectors;
    unsigned int irq_vector_flags;
    char name[PCI_NAME_LEN];
    u32 saved_config_space[PCI_CONFIG_DWORDS];
    pci_power_t current_state;
    bool wake_enabled;
};

struct pci_driver {
    const char *name;
    const struct pci_device_id *id_table;
    int (*probe)(struct pci_dev *dev, const struct pci_device_id *id);
    void (*remove)(struct pci_dev *dev);
    struct device_driver driver;
};

int __pci_register_driver(struct pci_driver *drv, struct module *owner, const char *mod_name);
#define pci_register_driver(drv) __pci_register_driver((drv), THIS_MODULE, KBUILD_MODNAME)
void pci_unregister_driver(struct pci_driver *drv);
int pci_enable_device(struct pci_dev *dev);
int pci_enable_device_mem(struct pci_dev *dev);
void pci_disable_device(struct pci_dev *dev);
int pcim_enable_device(struct pci_dev *dev);
int pcim_pin_device(struct pci_dev *dev);
void pci_set_master(struct pci_dev *dev);
void pci_clear_master(struct pci_dev *dev);
int pcie_capability_clear_and_set_word_locked(struct pci_dev *dev, int pos,
                                               u16 clear, u16 set);
int pcie_set_readrq(struct pci_dev *dev, int rq);
void pci_set_drvdata(struct pci_dev *dev, void *data);
void *pci_get_drvdata(struct pci_dev *dev);
const char *pci_name(const struct pci_dev *dev);
resource_size_t pci_resource_start(const struct pci_dev *dev, int bar);
resource_size_t pci_resource_end(const struct pci_dev *dev, int bar);
unsigned long pci_resource_flags(const struct pci_dev *dev, int bar);
resource_size_t pci_resource_len(const struct pci_dev *dev, int bar);
int pci_request_region(struct pci_dev *dev, int bar, const char *name);
void pci_release_region(struct pci_dev *dev, int bar);
int pci_select_bars(struct pci_dev *dev, unsigned long flags);
int pci_status_get_and_clear_errors(struct pci_dev *pdev);
int pci_request_selected_regions(struct pci_dev *dev, int bars, const char *name);
void pci_release_selected_regions(struct pci_dev *dev, int bars);
int pci_request_regions(struct pci_dev *dev, const char *name);
void pci_release_regions(struct pci_dev *dev);
int pcim_request_all_regions(struct pci_dev *dev, const char *name);
void pcim_release_all_regions(struct pci_dev *dev);
void __iomem *pci_iomap(struct pci_dev *dev, int bar, unsigned long maxlen);
void __iomem *pcim_iomap(struct pci_dev *dev, int bar, unsigned long maxlen);
void pcim_iounmap(struct pci_dev *dev, void __iomem *addr);
void __iomem *pci_ioremap_bar(struct pci_dev *dev, int bar);
void __iomem *pci_ioremap_wc_bar(struct pci_dev *dev, int bar);
void pci_iounmap(struct pci_dev *dev, void __iomem *addr);
int pci_enable_msi(struct pci_dev *dev);
void pci_disable_msi(struct pci_dev *dev);
int pci_msix_vec_count(struct pci_dev *dev);
int pci_alloc_irq_vectors(struct pci_dev *dev, int min_vecs, int max_vecs, unsigned int flags);
void pci_free_irq_vectors(struct pci_dev *dev);
int pci_irq_vector(struct pci_dev *dev, unsigned int nr);
int pci_read_config_byte(struct pci_dev *dev, int where, u8 *val);
int pci_read_config_word(struct pci_dev *dev, int where, u16 *val);
int pci_read_config_dword(struct pci_dev *dev, int where, u32 *val);
int pci_write_config_byte(struct pci_dev *dev, int where, u8 val);
int pci_write_config_word(struct pci_dev *dev, int where, u16 val);
int pci_write_config_dword(struct pci_dev *dev, int where, u32 val);
int pci_save_state(struct pci_dev *dev);
int pci_restore_state(struct pci_dev *dev);
int pci_set_power_state(struct pci_dev *dev, pci_power_t state);
pci_power_t pci_choose_state(struct pci_dev *dev, pm_message_t state);
int pci_enable_wake(struct pci_dev *dev, pci_power_t state, bool enable);

#endif
