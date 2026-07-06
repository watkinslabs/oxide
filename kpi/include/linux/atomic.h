#ifndef OXIDE_LINUX_ATOMIC_H
#define OXIDE_LINUX_ATOMIC_H

typedef struct { int counter; } atomic_t;
typedef struct { long long counter; } atomic64_t;

int atomic_read(atomic_t *v);
void atomic_set(atomic_t *v, int i);
void atomic_inc(atomic_t *v);
void atomic_dec(atomic_t *v);
void atomic_add(int i, atomic_t *v);
void atomic_sub(int i, atomic_t *v);
int atomic_dec_and_test(atomic_t *v);
int atomic_inc_return(atomic_t *v);

#endif
