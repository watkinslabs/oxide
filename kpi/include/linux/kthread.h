#ifndef OXIDE_LINUX_KTHREAD_H
#define OXIDE_LINUX_KTHREAD_H

#include <linux/types.h>

struct task_struct {
    int pid;
    int should_stop;
    int result;
    int done;
    int started;
    void *start;
};

struct task_struct *kthread_create(int (*threadfn)(void *data), void *data, const char namefmt[], ...);
int wake_up_process(struct task_struct *task);
int kthread_should_stop(void);
int kthread_stop(struct task_struct *task);
int kthread_associate_blkcg(void *css);
void set_current_state(int state);
void schedule(void);
long schedule_timeout(long timeout);

#define kthread_run(threadfn, data, namefmt, ...) ({ \
    struct task_struct *__task = kthread_create((threadfn), (data), (namefmt), ##__VA_ARGS__); \
    if (__task) wake_up_process(__task); \
    __task; \
})

#endif
