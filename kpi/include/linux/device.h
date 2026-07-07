#ifndef OXIDE_LINUX_DEVICE_H
#define OXIDE_LINUX_DEVICE_H

#include <linux/types.h>

struct device {
    u64 *dma_mask;
    u64 coherent_dma_mask;
    void *driver_data;
};

#endif
