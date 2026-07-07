#ifndef OXIDE_LINUX_HRTIMER_H
#define OXIDE_LINUX_HRTIMER_H

#include <linux/ktime.h>

enum hrtimer_restart {
    HRTIMER_NORESTART = 0,
    HRTIMER_RESTART = 1,
};

enum hrtimer_mode {
    HRTIMER_MODE_ABS = 0,
    HRTIMER_MODE_REL = 1,
};

struct hrtimer {
    ktime_t expires_ns;
    enum hrtimer_restart (*function)(struct hrtimer *);
    unsigned int active;
    unsigned long long oxide_id;
};

void hrtimer_init(struct hrtimer *timer, int clock_id, enum hrtimer_mode mode);
int hrtimer_start(struct hrtimer *timer, ktime_t time, enum hrtimer_mode mode);
int hrtimer_cancel(struct hrtimer *timer);

#endif
