#ifndef OXIDE_LINUX_WORKQUEUE_H
#define OXIDE_LINUX_WORKQUEUE_H

#include <linux/types.h>

struct work_struct {
    unsigned long data;
    void (*func)(struct work_struct *work);
};

struct delayed_work {
    struct work_struct work;
    unsigned long delay;
    unsigned long long oxide_id;
};

void init_work(struct work_struct *work, void (*func)(struct work_struct *work));
int schedule_work(struct work_struct *work);
void flush_scheduled_work(void);
int cancel_work_sync(struct work_struct *work);
void init_delayed_work(struct delayed_work *work, void (*func)(struct work_struct *work));
int schedule_delayed_work(struct delayed_work *work, unsigned long delay);
int cancel_delayed_work_sync(struct delayed_work *work);

#define INIT_WORK(work, fn) init_work((work), (fn))
#define DECLARE_WORK(name, fn) struct work_struct name = { .data = 0, .func = (fn) }
#define INIT_DELAYED_WORK(work, fn) init_delayed_work((work), (fn))

#endif
