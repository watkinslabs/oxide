#ifndef OXIDE_LINUX_JIFFIES_H
#define OXIDE_LINUX_JIFFIES_H

#include <linux/types.h>

#define HZ 100UL

extern unsigned long jiffies;
extern unsigned long long jiffies_64;

unsigned long msecs_to_jiffies(unsigned int m);
unsigned long usecs_to_jiffies(unsigned int u);
unsigned long nsecs_to_jiffies(unsigned long long n);
unsigned int jiffies_to_msecs(unsigned long j);
unsigned int jiffies_to_usecs(unsigned long j);

#define time_after(a, b) ((long)((b) - (a)) < 0)
#define time_before(a, b) time_after(b, a)
#define time_after_eq(a, b) ((long)((a) - (b)) >= 0)
#define time_before_eq(a, b) time_after_eq(b, a)

#endif
