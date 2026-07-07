#ifndef OXIDE_LINUX_ACPI_H
#define OXIDE_LINUX_ACPI_H

#include <linux/device.h>
#include <linux/errno.h>
#include <linux/mod_devicetable.h>
#include <linux/types.h>

#ifdef CONFIG_ACPI
#define ACPI_PTR(_ptr) (_ptr)
#else
#define ACPI_PTR(_ptr) NULL
#endif

struct acpi_device {
    char hid[ACPI_ID_LEN];
    char uid[ACPI_ID_LEN];
    void *driver_data;
};

#define ACPI_COMPANION(dev) ((dev) == NULL ? NULL : (dev)->acpi_node)
#define ACPI_HANDLE(dev) ACPI_COMPANION(dev)

const struct acpi_device_id *acpi_match_device(const struct acpi_device_id *ids, const struct device *dev);
struct acpi_device *acpi_dev_get_first_match_dev(const char *hid, const char *uid, s64 hrv);
void acpi_dev_put(struct acpi_device *adev);

#endif
