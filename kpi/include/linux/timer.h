#ifndef OXIDE_LINUX_TIMER_H
#define OXIDE_LINUX_TIMER_H

#include <linux/jiffies.h>
#include <linux/types.h>

struct timer_list {
    unsigned long expires;
    void (*function)(struct timer_list *);
    unsigned long data;
    unsigned int active;
    unsigned long long oxide_id;
};

void init_timer(struct timer_list *timer);
void setup_timer(struct timer_list *timer, void (*function)(struct timer_list *), unsigned long data);
void add_timer(struct timer_list *timer);
int mod_timer(struct timer_list *timer, unsigned long expires);
int del_timer(struct timer_list *timer);
int del_timer_sync(struct timer_list *timer);

#define timer_setup(timer, callback, flags) do { (void)(flags); setup_timer((timer), (callback), 0); } while (0)

#endif
