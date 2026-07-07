#ifndef OXIDE_LINUX_SYSFS_H
#define OXIDE_LINUX_SYSFS_H

#include <linux/compiler_types.h>
#include <linux/types.h>

#define PAGE_SIZE 4096UL

struct attribute;
struct kobject;

int sysfs_emit(char *buf, const char *fmt, ...) __printf(2, 3);
int sysfs_emit_at(char *buf, int at, const char *fmt, ...) __printf(3, 4);

#endif
