#ifndef OXIDE_LINUX_DEBUGFS_H
#define OXIDE_LINUX_DEBUGFS_H

#include <linux/fs.h>
#include <linux/types.h>

struct dentry {
    void *d_inode;
    void *d_fsdata;
};

int debugfs_initialized(void);
struct dentry *debugfs_create_dir(const char *name, struct dentry *parent);
struct dentry *debugfs_create_file(const char *name, umode_t mode, struct dentry *parent, void *data, const struct file_operations *fops);
struct dentry *debugfs_create_u8(const char *name, umode_t mode, struct dentry *parent, u8 *value);
struct dentry *debugfs_create_u16(const char *name, umode_t mode, struct dentry *parent, u16 *value);
struct dentry *debugfs_create_u32(const char *name, umode_t mode, struct dentry *parent, u32 *value);
struct dentry *debugfs_create_u64(const char *name, umode_t mode, struct dentry *parent, u64 *value);
struct dentry *debugfs_create_x8(const char *name, umode_t mode, struct dentry *parent, u8 *value);
struct dentry *debugfs_create_x16(const char *name, umode_t mode, struct dentry *parent, u16 *value);
struct dentry *debugfs_create_x32(const char *name, umode_t mode, struct dentry *parent, u32 *value);
struct dentry *debugfs_create_x64(const char *name, umode_t mode, struct dentry *parent, u64 *value);
struct dentry *debugfs_create_bool(const char *name, umode_t mode, struct dentry *parent, bool *value);
void debugfs_remove(struct dentry *dentry);
void debugfs_remove_recursive(struct dentry *dentry);
struct dentry *debugfs_lookup(const char *name, struct dentry *parent);

#endif
