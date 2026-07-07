#ifndef OXIDE_LINUX_DEVICE_H
#define OXIDE_LINUX_DEVICE_H

#include <linux/dynamic_debug.h>
#include <linux/gfp.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/pm.h>
#include <linux/types.h>

#define OXIDE_DEVICE_NAME_LEN 64

struct acpi_device;
struct device_node;
struct attribute {
    const char *name;
    umode_t mode;
};

struct device_attribute;
struct device {
    u64 *dma_mask;
    u64 coherent_dma_mask;
    void *driver_data;
    struct device *parent;
    struct bus_type *bus;
    struct class *class;
    struct device_driver *driver;
    const char *init_name;
    char name[OXIDE_DEVICE_NAME_LEN];
    void (*release)(struct device *dev);
    struct device_node *of_node;
    struct acpi_device *acpi_node;
    struct dev_pm_info power;
};

struct device_driver {
    const char *name;
    struct bus_type *bus;
    struct module *owner;
    int (*probe)(struct device *dev);
    int (*remove)(struct device *dev);
    const struct of_device_id *of_match_table;
    const struct acpi_device_id *acpi_match_table;
    const struct dev_pm_ops *pm;
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
