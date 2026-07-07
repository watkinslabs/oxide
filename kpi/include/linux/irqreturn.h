#ifndef OXIDE_LINUX_IRQRETURN_H
#define OXIDE_LINUX_IRQRETURN_H

enum irqreturn {
    IRQ_NONE = 0,
    IRQ_HANDLED = 1,
    IRQ_WAKE_THREAD = 2,
};

typedef enum irqreturn irqreturn_t;

#endif
