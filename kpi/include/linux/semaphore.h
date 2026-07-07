#ifndef OXIDE_LINUX_SEMAPHORE_H
#define OXIDE_LINUX_SEMAPHORE_H

#include <linux/spinlock.h>

struct semaphore { raw_spinlock_t lock; unsigned int count; unsigned int wait_seq; };

void sema_init(struct semaphore *sem, int val);
void down(struct semaphore *sem);
int down_interruptible(struct semaphore *sem);
int down_trylock(struct semaphore *sem);
void up(struct semaphore *sem);

#endif
