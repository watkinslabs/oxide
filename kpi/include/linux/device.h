#ifndef OXIDE_LINUX_DEVICE_H
#define OXIDE_LINUX_DEVICE_H

#include <linux/dynamic_debug.h>
#include <linux/gfp.h>
#include <linux/kobject.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/pm.h>
#include <linux/types.h>

#define OXIDE_DEVICE_NAME_LEN 64

struct acpi_device;
struct device_node;
struct attribute_group;
struct driver_private;
struct device_private;
struct device_type;
struct dev_pm_domain;
struct em_perf_domain;
struct dev_pin_info;
struct dma_map_ops;
struct bus_dma_region;
struct device_dma_parameters;
struct cma;
struct io_tlb_mem;
struct fwnode_handle;
struct iommu_group;
struct dev_iommu;
struct device_physical_location;
struct device_driver;
struct bus_type;
struct class;
struct device {
    struct kobject kobj;
    struct device *parent;
    struct device_private *p;
    const char *init_name;
    const struct device_type *type;
    const struct bus_type *bus;
    struct device_driver *driver;
    void *platform_data;
    void *driver_data;
    struct { const char *name; u32 lock; } driver_override;
    u8 mutex[32];
    u8 links[56];
    struct dev_pm_info power;
    struct dev_pm_domain *pm_domain;
    struct em_perf_domain *em_pd;
    struct dev_pin_info *pins;
    u8 msi[16];
    const struct dma_map_ops *dma_ops;
    u64 *dma_mask;
    u64 coherent_dma_mask;
    u64 bus_dma_limit;
    const struct bus_dma_region *dma_range_map;
    struct device_dma_parameters *dma_parms;
    struct list_head dma_pools;
    struct cma *cma_area;
    struct io_tlb_mem *dma_io_tlb_mem;
    struct device_node *of_node;
    struct fwnode_handle *fwnode;
    int numa_node;
    dev_t devt;
    u32 id;
    u32 devres_lock;
    struct list_head devres_head;
    const struct class *class;
    const struct attribute_group **groups;
    void (*release)(struct device *dev);
    struct iommu_group *iommu_group;
    struct dev_iommu *iommu;
    struct device_physical_location *physical_location;
    int removable;
    u32 flags;
};
struct attribute {
    const char *name;
    umode_t mode;
};

struct device_attribute;

struct device_driver {
    const char *name;
    struct bus_type *bus;
    struct module *owner;
    const char *mod_name;
    bool suppress_bind_attrs;
    int probe_type;
    const struct of_device_id *of_match_table;
    const struct acpi_device_id *acpi_match_table;
    int (*probe)(struct device *dev);
    void (*sync_state)(struct device *dev);
    int (*remove)(struct device *dev);
    void (*shutdown)(struct device *dev);
    int (*suspend)(struct device *dev, int state);
    int (*resume)(struct device *dev);
    const struct attribute_group * const *groups;
    const struct attribute_group * const *dev_groups;
    const struct dev_pm_ops *pm;
    void (*coredump)(struct device *dev);
    struct driver_private *p;
    struct { void (*post_unbind_rust)(struct device *dev); } p_cb;
};

struct bus_type {
    const char *name;
    void *private;
};

struct class {
    const char *name;
    struct module *owner;
    void *private;
};

struct device_attribute {
    struct attribute attr;
    ssize_t (*show)(struct device *dev, struct device_attribute *attr, char *buf);
    ssize_t (*store)(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
};

#define DEVICE_ATTR(_name, _mode, _show, _store) \
    struct device_attribute dev_attr_##_name = { { #_name, (_mode) }, (_show), (_store) }

void device_initialize(struct device *dev);
int device_add(struct device *dev);
void device_del(struct device *dev);
int device_register(struct device *dev);
void device_unregister(struct device *dev);
struct device *get_device(struct device *dev);
void put_device(struct device *dev);
void dev_set_drvdata(struct device *dev, void *data);
void *dev_get_drvdata(const struct device *dev);
const char *dev_name(const struct device *dev);
const char *dev_driver_string(const struct device *dev);
int dev_err_probe(const struct device *dev, int err, const char *fmt, ...);
const void *device_get_match_data(const struct device *dev);
int dev_set_name(struct device *dev, const char *fmt, ...);
struct device *root_device_register(const char *name);
void root_device_unregister(struct device *dev);
struct class *__class_create(struct module *owner, const char *name);
#define class_create(owner, name) __class_create((owner), (name))
int class_register(struct class *class);
void class_unregister(struct class *class);
void class_destroy(struct class *class);
int bus_register(struct bus_type *bus);
void bus_unregister(struct bus_type *bus);
int driver_register(struct device_driver *drv);
void driver_unregister(struct device_driver *drv);
struct device *device_create(struct class *class, struct device *parent, dev_t devt, void *drvdata, const char *fmt, ...);
void device_destroy(struct class *class, dev_t devt);
int device_create_file(struct device *dev, const struct device_attribute *attr);
void device_remove_file(struct device *dev, const struct device_attribute *attr);
void *devm_kmalloc(struct device *dev, size_t size, gfp_t flags);
void *devm_kzalloc(struct device *dev, size_t size, gfp_t flags);
void devm_kfree(struct device *dev, const void *p);
int devm_add_action_or_reset(struct device *dev, void (*action)(void *), void *data);
void devm_remove_action(struct device *dev, void (*action)(void *), void *data);

void _dev_err(const struct device *dev, const char *fmt, ...);
void _dev_warn(const struct device *dev, const char *fmt, ...);
void _dev_info(const struct device *dev, const char *fmt, ...);
void _dev_dbg(const struct device *dev, const char *fmt, ...);
#define dev_err(dev, fmt, ...) _dev_err((dev), (fmt), ##__VA_ARGS__)
#define dev_warn(dev, fmt, ...) _dev_warn((dev), (fmt), ##__VA_ARGS__)
#define dev_info(dev, fmt, ...) _dev_info((dev), (fmt), ##__VA_ARGS__)
#define dev_dbg(dev, fmt, ...) _dev_dbg((dev), (fmt), ##__VA_ARGS__)

#endif
