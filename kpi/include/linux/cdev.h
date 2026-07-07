#ifndef OXIDE_LINUX_CDEV_H
#define OXIDE_LINUX_CDEV_H

#include <linux/fs.h>
#include <linux/kdev_t.h>
#include <linux/types.h>

struct cdev {
    const struct file_operations *ops;
    struct module *owner;
    dev_t dev;
    unsigned int count;
    unsigned int added;
    void *private;
};

void cdev_init(struct cdev *cdev, const struct file_operations *fops);
struct cdev *cdev_alloc(void);
int cdev_add(struct cdev *cdev, dev_t dev, unsigned int count);
void cdev_del(struct cdev *cdev);
int alloc_chrdev_region(dev_t *dev, unsigned int firstminor, unsigned int count, const char *name);
int register_chrdev_region(dev_t dev, unsigned int count, const char *name);
void unregister_chrdev_region(dev_t dev, unsigned int count);
int register_chrdev(unsigned int major, const char *name, const struct file_operations *fops);
void unregister_chrdev(unsigned int major, const char *name);

#endif
