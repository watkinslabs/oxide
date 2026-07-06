#ifndef OXIDE_LINUX_KERNEL_H
#define OXIDE_LINUX_KERNEL_H

#include <linux/bits.h>
#include <linux/build_bug.h>
#include <linux/compiler_types.h>
#include <linux/stddef.h>
#include <linux/types.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + BUILD_BUG_ON_ZERO(__builtin_types_compatible_p(typeof(arr), typeof(&(arr)[0]))))
#define container_of(ptr, type, member) ({ const typeof(((type *)0)->member) *__mptr = (ptr); (type *)((char *)__mptr - offsetof(type, member)); })
#define min(x, y) ({ typeof(x) _min1 = (x); typeof(y) _min2 = (y); _min1 < _min2 ? _min1 : _min2; })
#define max(x, y) ({ typeof(x) _max1 = (x); typeof(y) _max2 = (y); _max1 > _max2 ? _max1 : _max2; })
#define clamp(val, lo, hi) min((typeof(val))max(val, lo), hi)

int printk(const char *fmt, ...) __printf(1, 2);
#define pr_emerg(fmt, ...) printk(fmt, ##__VA_ARGS__)
#define pr_alert(fmt, ...) printk(fmt, ##__VA_ARGS__)
#define pr_crit(fmt, ...) printk(fmt, ##__VA_ARGS__)
#define pr_err(fmt, ...) printk(fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...) printk(fmt, ##__VA_ARGS__)
#define pr_notice(fmt, ...) printk(fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...) printk(fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...) printk(fmt, ##__VA_ARGS__)

#endif
