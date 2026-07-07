#ifndef OXIDE_LINUX_PLATFORM_DEVICE_H
#define OXIDE_LINUX_PLATFORM_DEVICE_H

#include <linux/device.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/types.h>

#define PLATFORM_DEVID_NONE (-1)
#define PLATFORM_DEVID_AUTO (-2)

struct platform_device {
    const char *name;
    int id;
    struct device dev;
    u32 num_resources;
    struct resource *resource;
    void *driver_data;
    struct platform_driver *driver;
    const struct platform_device_id *id_entry;
    u32 registered;
};

struct platform_driver {
    int (*probe)(struct platform_device *pdev);
    int (*remove)(struct platform_device *pdev);
    void (*shutdown)(struct platform_device *pdev);
    struct device_driver driver;
    const struct platform_device_id *id_table;
};

#define to_platform_device(_dev) container_of((_dev), struct platform_device, dev)
#define platform_get_drvdata(_pdev) dev_get_drvdata(&(_pdev)->dev)
#define platform_set_drvdata(_pdev, _data) dev_set_drvdata(&(_pdev)->dev, (_data))

int __platform_driver_register(struct platform_driver *drv, struct module *owner);
#define platform_driver_register(drv) __platform_driver_register((drv), THIS_MODULE)
void platform_driver_unregister(struct platform_driver *drv);
struct platform_device *platform_device_alloc(const char *name, int id);
int platform_device_add(struct platform_device *pdev);
void platform_device_del(struct platform_device *pdev);
void platform_device_put(struct platform_device *pdev);
int platform_device_register(struct platform_device *pdev);
void platform_device_unregister(struct platform_device *pdev);
struct resource *platform_get_resource(struct platform_device *pdev, unsigned int type, unsigned int num);
struct resource *platform_get_resource_byname(struct platform_device *pdev, unsigned int type, const char *name);
int platform_get_irq(struct platform_device *pdev, unsigned int num);
int platform_get_irq_optional(struct platform_device *pdev, unsigned int num);
void __iomem *devm_platform_ioremap_resource(struct platform_device *pdev, unsigned int index);
void __iomem *devm_platform_get_and_ioremap_resource(struct platform_device *pdev, unsigned int index, struct resource **res);

#define module_platform_driver(__platform_driver) \
    module_driver(__platform_driver, platform_driver_register, platform_driver_unregister)

#endif
