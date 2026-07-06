#ifndef OXIDE_LINUX_COMPILER_TYPES_H
#define OXIDE_LINUX_COMPILER_TYPES_H

#include <linux/compiler_attributes.h>

#define __user
#define __kernel
#define __iomem
#define __percpu
#define __rcu
#define __force
#define __must_check __attribute__((__warn_unused_result__))
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#endif
