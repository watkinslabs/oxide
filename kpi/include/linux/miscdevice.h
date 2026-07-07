#ifndef OXIDE_LINUX_MISCDEVICE_H
#define OXIDE_LINUX_MISCDEVICE_H

#include <linux/cdev.h>
#include <linux/types.h>

#define MISC_MAJOR 10
#define MISC_DYNAMIC_MINOR 255

struct miscdevice {
    int minor;
    const char *name;
    const struct file_operations *fops;
    void *parent;
    void *this_device;
    umode_t mode;
    const char *nodename;
    struct cdev cdev;
    unsigned int registered;
};

int misc_register(struct miscdevice *misc);
int misc_deregister(struct miscdevice *misc);

#endif
