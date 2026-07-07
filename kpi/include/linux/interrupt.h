#ifndef OXIDE_LINUX_INTERRUPT_H
#define OXIDE_LINUX_INTERRUPT_H

#include <linux/irqreturn.h>
#include <linux/types.h>

struct cpumask;
typedef irqreturn_t (*irq_handler_t)(int, void *);

#define IRQF_SHARED 0x00000080UL
#define IRQF_TRIGGER_NONE 0x00000000UL
#define IRQF_TRIGGER_RISING 0x00000001UL
#define IRQF_TRIGGER_FALLING 0x00000002UL
#define IRQF_TRIGGER_HIGH 0x00000004UL
#define IRQF_TRIGGER_LOW 0x00000008UL
#define IRQF_ONESHOT 0x00002000UL

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

int request_irq(unsigned int irq, irq_handler_t handler, unsigned long flags, const char *name, void *dev);
int request_threaded_irq(unsigned int irq, irq_handler_t handler, irq_handler_t thread_fn, unsigned long flags, const char *name, void *dev);
void free_irq(unsigned int irq, void *dev_id);
void enable_irq(unsigned int irq);
void disable_irq(unsigned int irq);
void disable_irq_nosync(unsigned int irq);
void synchronize_irq(unsigned int irq);
int irq_set_affinity_hint(unsigned int irq, const struct cpumask *m);
int irq_update_affinity_hint(unsigned int irq, const struct cpumask *m);
int in_irq(void);
int in_interrupt(void);

#endif
