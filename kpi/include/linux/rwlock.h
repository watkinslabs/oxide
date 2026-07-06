#ifndef OXIDE_LINUX_RWLOCK_H
#define OXIDE_LINUX_RWLOCK_H

typedef struct { int state; } rwlock_t;

void rwlock_init(rwlock_t *lock);
void read_lock(rwlock_t *lock);
int read_trylock(rwlock_t *lock);
void read_unlock(rwlock_t *lock);
void write_lock(rwlock_t *lock);
int write_trylock(rwlock_t *lock);
void write_unlock(rwlock_t *lock);

#endif
