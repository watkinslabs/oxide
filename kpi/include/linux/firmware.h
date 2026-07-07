#ifndef OXIDE_LINUX_FIRMWARE_H
#define OXIDE_LINUX_FIRMWARE_H

#include <linux/device.h>
#include <linux/types.h>

struct firmware {
    size_t size;
    const u8 *data;
    struct page **pages;
    void *priv;
};

int request_firmware(const struct firmware **fw, const char *name, struct device *device);
int request_firmware_direct(const struct firmware **fw, const char *name, struct device *device);
int firmware_request(const struct firmware **fw, const char *name, struct device *device);
int firmware_request_nowarn(const struct firmware **fw, const char *name, struct device *device);
void release_firmware(const struct firmware *fw);

#endif
