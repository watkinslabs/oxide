#ifndef OXIDE_LINUX_SCHED_H
#define OXIDE_LINUX_SCHED_H

#define TASK_RUNNING 0
#define TASK_INTERRUPTIBLE 1
#define TASK_UNINTERRUPTIBLE 2

void set_current_state(int state);
void schedule(void);

#endif
