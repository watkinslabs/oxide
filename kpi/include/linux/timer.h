#ifndef OXIDE_LINUX_TIMER_H
#define OXIDE_LINUX_TIMER_H

#include <linux/jiffies.h>
#include <linux/types.h>

struct timer_list {
    struct {
        void *next;
        void **pprev;
    } entry;
    unsigned long expires;
    void (*function)(struct timer_list *);
    unsigned int flags;
};

void init_timer(struct timer_list *timer);
void setup_timer(struct timer_list *timer, void (*function)(struct timer_list *), unsigned long data);
void timer_init_key(struct timer_list *timer, void (*function)(struct timer_list *),
                    unsigned int flags, const char *name, void *key);
void add_timer(struct timer_list *timer);
int mod_timer(struct timer_list *timer, unsigned long expires);
int timer_reduce(struct timer_list *timer, unsigned long expires);
int del_timer(struct timer_list *timer);
int del_timer_sync(struct timer_list *timer);
int timer_delete(struct timer_list *timer);
int timer_delete_sync(struct timer_list *timer);
int timer_shutdown_sync(struct timer_list *timer);

#define timer_setup(timer, callback, flags) do { (void)(flags); setup_timer((timer), (callback), 0); } while (0)

#endif
