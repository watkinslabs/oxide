#ifndef OXIDE_LINUX_MOD_DEVICETABLE_H
#define OXIDE_LINUX_MOD_DEVICETABLE_H

#include <linux/types.h>

#define PLATFORM_NAME_SIZE 20
#define ACPI_ID_LEN 9

struct pci_device_id {
    __u32 vendor;
    __u32 device;
    __u32 subvendor;
    __u32 subdevice;
    __u32 class;
    __u32 class_mask;
    unsigned long driver_data;
};

struct usb_device_id {
    __u16 match_flags;
    __u16 idVendor;
    __u16 idProduct;
    __u16 bcdDevice_lo;
    __u16 bcdDevice_hi;
    __u8 bDeviceClass;
    __u8 bDeviceSubClass;
    __u8 bDeviceProtocol;
    __u8 bInterfaceClass;
    __u8 bInterfaceSubClass;
    __u8 bInterfaceProtocol;
    unsigned long driver_info;
};

struct platform_device_id {
    char name[PLATFORM_NAME_SIZE];
    unsigned long driver_data;
};

struct acpi_device_id {
    __u8 id[ACPI_ID_LEN];
    unsigned long driver_data;
};

struct of_device_id {
    const char *name;
    const char *type;
    const char *compatible;
    const void *data;
};

#endif
