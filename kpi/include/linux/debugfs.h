#ifndef OXIDE_LINUX_DEBUGFS_H
#define OXIDE_LINUX_DEBUGFS_H

#include <linux/compiler_types.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/types.h>

struct dentry {
    void *d_inode;
    void *d_fsdata;
};

struct debugfs_blob_wrapper {
    void *data;
    unsigned long size;
};

struct debugfs_reg32 {
    char *name;
    unsigned long offset;
};

struct debugfs_regset32 {
    const struct debugfs_reg32 *regs;
    int nregs;
    void __iomem *base;
    struct device *dev;
};

int debugfs_initialized(void);
struct dentry *debugfs_create_dir(const char *name, struct dentry *parent);
struct dentry *debugfs_create_file(const char *name, umode_t mode, struct dentry *parent, void *data, const struct file_operations *fops);
struct dentry *debugfs_create_file_size(const char *name, umode_t mode, struct dentry *parent, void *data, const struct file_operations *fops, loff_t file_size);
struct dentry *debugfs_create_u8(const char *name, umode_t mode, struct dentry *parent, u8 *value);
struct dentry *debugfs_create_u16(const char *name, umode_t mode, struct dentry *parent, u16 *value);
struct dentry *debugfs_create_u32(const char *name, umode_t mode, struct dentry *parent, u32 *value);
struct dentry *debugfs_create_u64(const char *name, umode_t mode, struct dentry *parent, u64 *value);
struct dentry *debugfs_create_x8(const char *name, umode_t mode, struct dentry *parent, u8 *value);
struct dentry *debugfs_create_x16(const char *name, umode_t mode, struct dentry *parent, u16 *value);
struct dentry *debugfs_create_x32(const char *name, umode_t mode, struct dentry *parent, u32 *value);
struct dentry *debugfs_create_x64(const char *name, umode_t mode, struct dentry *parent, u64 *value);
struct dentry *debugfs_create_bool(const char *name, umode_t mode, struct dentry *parent, bool *value);
struct dentry *debugfs_create_blob(const char *name, umode_t mode, struct dentry *parent, struct debugfs_blob_wrapper *blob);
void debugfs_create_regset32(const char *name, umode_t mode, struct dentry *parent, struct debugfs_regset32 *regset);
void debugfs_print_regs32(struct seq_file *s, const struct debugfs_reg32 *regs, int nregs, void __iomem *base, char *prefix);
struct dentry *debugfs_create_symlink(const char *name, struct dentry *parent, const char *target);
void debugfs_remove(struct dentry *dentry);
void debugfs_remove_recursive(struct dentry *dentry);
struct dentry *debugfs_lookup(const char *name, struct dentry *parent);

int simple_attr_open(struct inode *inode, struct file *file,
                     int (*get)(void *data, u64 *value),
                     int (*set)(void *data, u64 value),
                     const char *fmt);
ssize_t simple_attr_read(struct file *file, char *buf, size_t count, loff_t *ppos);
ssize_t simple_attr_write(struct file *file, const char *buf, size_t count, loff_t *ppos);
int simple_attr_release(struct inode *inode, struct file *file);

#define DEFINE_SIMPLE_ATTRIBUTE(__fops, __get, __set, __fmt)             \
    static int __fops##_open(struct inode *inode, struct file *file)      \
    {                                                                    \
        return simple_attr_open(inode, file, __get, __set, __fmt);       \
    }                                                                    \
    static const struct file_operations __fops = {                       \
        .owner = THIS_MODULE,                                            \
        .open = __fops##_open,                                           \
        .read = simple_attr_read,                                        \
        .write = simple_attr_write,                                      \
        .release = simple_attr_release,                                  \
        .llseek = noop_llseek,                                           \
    }

#endif
