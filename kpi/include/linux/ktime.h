#ifndef OXIDE_LINUX_KTIME_H
#define OXIDE_LINUX_KTIME_H

#include <linux/types.h>

typedef s64 ktime_t;

#define NSEC_PER_USEC 1000L
#define NSEC_PER_MSEC 1000000L
#define NSEC_PER_SEC 1000000000L

ktime_t ktime_get(void);
s64 ktime_get_ns(void);
ktime_t ktime_set(const long secs, const unsigned long nsecs);
ktime_t ns_to_ktime(s64 ns);
s64 ktime_to_ns(ktime_t kt);
ktime_t ktime_add_ns(ktime_t kt, u64 ns);
ktime_t ktime_sub_ns(ktime_t kt, u64 ns);

#endif
