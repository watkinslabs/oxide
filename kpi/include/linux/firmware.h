#ifndef OXIDE_LINUX_FIRMWARE_H
#define OXIDE_LINUX_FIRMWARE_H

#include <linux/device.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/types.h>

#define FW_ACTION_NOUEVENT 0
#define FW_ACTION_UEVENT 1

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
int firmware_request_platform(const struct firmware **fw, const char *name, struct device *device);
int firmware_request_cache(struct device *device, const char *name);
int request_firmware_into_buf(const struct firmware **fw, const char *name,
                              struct device *device, void *buf, size_t size);
int request_partial_firmware_into_buf(const struct firmware **fw, const char *name,
                                      struct device *device, void *buf, size_t size,
                                      size_t offset);
int request_firmware_nowait(struct module *module, bool uevent, const char *name,
                            struct device *device, gfp_t gfp, void *context,
                            void (*cont)(const struct firmware *fw, void *context));
int firmware_request_nowait_nowarn(struct module *module, const char *name,
                                   struct device *device, gfp_t gfp, void *context,
                                   void (*cont)(const struct firmware *fw, void *context));
void release_firmware(const struct firmware *fw);

#endif
