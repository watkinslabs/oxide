#ifndef OXIDE_LINUX_FS_H
#define OXIDE_LINUX_FS_H

#include <linux/types.h>

struct inode {
    dev_t i_rdev;
    void *i_private;
};

struct file {
    void *private_data;
};

struct poll_table_struct;
struct vm_area_struct;
typedef struct poll_table_struct poll_table;

struct file_operations {
    struct module *owner;
    int (*open)(struct inode *inode, struct file *file);
    ssize_t (*read)(struct file *file, char *buf, size_t count, loff_t *ppos);
    ssize_t (*write)(struct file *file, const char *buf, size_t count, loff_t *ppos);
    long (*unlocked_ioctl)(struct file *file, unsigned int cmd, unsigned long arg);
    int (*release)(struct inode *inode, struct file *file);
    unsigned int (*poll)(struct file *file, poll_table *wait);
    int (*mmap)(struct file *file, struct vm_area_struct *vma);
    void *llseek;
};

loff_t noop_llseek(struct file *file, loff_t offset, int whence);
int nonseekable_open(struct inode *inode, struct file *file);

#endif
