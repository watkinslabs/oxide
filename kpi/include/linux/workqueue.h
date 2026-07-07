#ifndef OXIDE_LINUX_WORKQUEUE_H
#define OXIDE_LINUX_WORKQUEUE_H

#include <linux/types.h>
#include <linux/timer.h>

struct work_struct {
    unsigned long data;
    struct {
        void *next;
        void *prev;
    } entry;
    void (*func)(struct work_struct *work);
};

struct workqueue_struct {
    unsigned int flags;
    int max_active;
    int destroyed;
    char name[32];
};

struct delayed_work {
    struct work_struct work;
    struct timer_list timer;
    struct workqueue_struct *wq;
    int cpu;
};

struct workqueue_struct *alloc_workqueue(const char *fmt, unsigned int flags, int max_active, ...);
void destroy_workqueue(struct workqueue_struct *wq);
void __flush_workqueue(struct workqueue_struct *wq);
void init_work(struct work_struct *work, void (*func)(struct work_struct *work));
int schedule_work(struct work_struct *work);
int queue_work_on(int cpu, struct workqueue_struct *wq, struct work_struct *work);
void flush_scheduled_work(void);
int flush_work(struct work_struct *work);
int cancel_work_sync(struct work_struct *work);
int disable_work(struct work_struct *work);
int disable_work_sync(struct work_struct *work);
void enable_work(struct work_struct *work);
void init_delayed_work(struct delayed_work *work, void (*func)(struct work_struct *work));
int schedule_delayed_work(struct delayed_work *work, unsigned long delay);
int queue_delayed_work_on(int cpu, struct workqueue_struct *wq, struct delayed_work *work,
                          unsigned long delay);
int mod_delayed_work_on(int cpu, struct workqueue_struct *wq, struct delayed_work *work,
                        unsigned long delay);
int cancel_delayed_work(struct delayed_work *work);
int cancel_delayed_work_sync(struct delayed_work *work);
void delayed_work_timer_fn(struct timer_list *timer);

#define INIT_WORK(work, fn) init_work((work), (fn))
#define DECLARE_WORK(name, fn) struct work_struct name = { .data = 0, .entry = { 0, 0 }, .func = (fn) }
#define INIT_DELAYED_WORK(work, fn) init_delayed_work((work), (fn))

#endif
