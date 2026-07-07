#ifndef OXIDE_LINUX_COMPLETION_H
#define OXIDE_LINUX_COMPLETION_H

struct completion { unsigned int done; };

void init_completion(struct completion *x);
void reinit_completion(struct completion *x);
void complete(struct completion *x);
void complete_all(struct completion *x);
void wait_for_completion(struct completion *x);
int wait_for_completion_interruptible(struct completion *x);
unsigned long wait_for_completion_timeout(struct completion *x, unsigned long timeout);
int try_wait_for_completion(struct completion *x);
int completion_done(struct completion *x);

#endif
