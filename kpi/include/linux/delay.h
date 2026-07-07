#ifndef OXIDE_LINUX_DELAY_H
#define OXIDE_LINUX_DELAY_H

void msleep(unsigned int msecs);
unsigned long msleep_interruptible(unsigned int msecs);
void usleep_range(unsigned long min, unsigned long max);
void usleep_range_state(unsigned long min, unsigned long max, unsigned int state);
void udelay(unsigned long usecs);
void __udelay(unsigned long usecs);
void __const_udelay(unsigned long xloops);
void mdelay(unsigned long msecs);

#endif
