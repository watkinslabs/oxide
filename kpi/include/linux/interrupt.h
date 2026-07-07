#ifndef OXIDE_LINUX_INTERRUPT_H
#define OXIDE_LINUX_INTERRUPT_H

#include <linux/types.h>

struct tasklet_struct {
    struct tasklet_struct *next;
    unsigned long state;
    unsigned long count;
    void (*func)(unsigned long);
    unsigned long data;
};

void tasklet_init(struct tasklet_struct *t, void (*func)(unsigned long), unsigned long data);
void tasklet_schedule(struct tasklet_struct *t);
void tasklet_kill(struct tasklet_struct *t);
void tasklet_disable(struct tasklet_struct *t);
void tasklet_enable(struct tasklet_struct *t);

#define DECLARE_TASKLET(name, func, data) struct tasklet_struct name = { 0, 0, 0, (func), (data) }

#endif
