#ifndef OXIDE_LINUX_MOD_DEVICETABLE_H
#define OXIDE_LINUX_MOD_DEVICETABLE_H

#include <linux/types.h>

struct pci_device_id {
    __u32 vendor;
    __u32 device;
    __u32 subvendor;
    __u32 subdevice;
    __u32 class;
    __u32 class_mask;
    unsigned long driver_data;
};

#endif
