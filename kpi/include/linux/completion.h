#ifndef OXIDE_LINUX_COMPLETION_H
#define OXIDE_LINUX_COMPLETION_H

struct completion { unsigned int done; };

void init_completion(struct completion *x);
void reinit_completion(struct completion *x);
void complete(struct completion *x);
void complete_all(struct completion *x);
void wait_for_completion(struct completion *x);
int try_wait_for_completion(struct completion *x);
int completion_done(struct completion *x);

#endif
