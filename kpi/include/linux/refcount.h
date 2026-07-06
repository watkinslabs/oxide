#ifndef OXIDE_LINUX_REFCOUNT_H
#define OXIDE_LINUX_REFCOUNT_H

typedef struct { unsigned int refs; } refcount_t;

void refcount_set(refcount_t *r, unsigned int n);
unsigned int refcount_read(refcount_t *r);
void refcount_inc(refcount_t *r);
int refcount_dec_and_test(refcount_t *r);

#endif
