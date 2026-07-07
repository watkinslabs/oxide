#ifndef OXIDE_LINUX_OF_H
#define OXIDE_LINUX_OF_H

#include <linux/device.h>
#include <linux/errno.h>
#include <linux/mod_devicetable.h>
#include <linux/types.h>

#ifdef CONFIG_OF
#define of_match_ptr(_ptr) (_ptr)
#else
#define of_match_ptr(_ptr) NULL
#endif

struct device_node {
    const char *name;
    const char *type;
    const char *compatible;
    void *data;
};

const struct of_device_id *of_match_device(const struct of_device_id *matches, const struct device *dev);
int of_property_read_u32(const struct device_node *np, const char *propname, u32 *out_value);
bool of_property_read_bool(const struct device_node *np, const char *propname);

#endif
