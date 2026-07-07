#ifndef OXIDE_LINUX_SEQ_FILE_H
#define OXIDE_LINUX_SEQ_FILE_H

#include <linux/compiler_attributes.h>
#include <linux/fs.h>
#include <linux/types.h>

struct seq_file {
    void *private;
};

struct seq_operations {
    void *(*start)(struct seq_file *m, loff_t *pos);
    void (*stop)(struct seq_file *m, void *v);
    void *(*next)(struct seq_file *m, void *v, loff_t *pos);
    int (*show)(struct seq_file *m, void *v);
};

int seq_open(struct file *file, const struct seq_operations *op);
int single_open(struct file *file, int (*show)(struct seq_file *, void *), void *data);
ssize_t seq_read(struct file *file, char *buf, size_t size, loff_t *ppos);
loff_t seq_lseek(struct file *file, loff_t offset, int whence);
int seq_release(struct inode *inode, struct file *file);
int single_release(struct inode *inode, struct file *file);
int seq_putc(struct seq_file *m, char c);
int seq_puts(struct seq_file *m, const char *s);
int seq_write(struct seq_file *m, const void *data, size_t len);
int seq_printf(struct seq_file *m, const char *fmt, ...) __printf(2, 3);

#endif
