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
    HRTIMER_MODE_PINNED = 2,
    HRTIMER_MODE_SOFT = 4,
    HRTIMER_MODE_HARD = 8,
};

struct hrtimer {
    struct {
        struct {
            unsigned long parent_color;
            void *right;
            void *left;
        } node;
        ktime_t expires;
    } node;
    ktime_t _softexpires;
    enum hrtimer_restart (*function)(struct hrtimer *);
    void *base;
    unsigned char state;
    unsigned char is_rel;
    unsigned char is_soft;
    unsigned char is_hard;
};

void hrtimer_init(struct hrtimer *timer, int clock_id, enum hrtimer_mode mode);
void hrtimer_setup(struct hrtimer *timer, enum hrtimer_restart (*function)(struct hrtimer *),
                   enum hrtimer_mode mode);
int hrtimer_start(struct hrtimer *timer, ktime_t time, enum hrtimer_mode mode);
void hrtimer_start_range_ns(struct hrtimer *timer, ktime_t time, u64 delta_ns,
                            enum hrtimer_mode mode);
int hrtimer_cancel(struct hrtimer *timer);
int hrtimer_active(const struct hrtimer *timer);
u64 hrtimer_forward(struct hrtimer *timer, ktime_t now, ktime_t interval);

#endif
