#ifndef OXIDE_LINUX_MUTEX_H
#define OXIDE_LINUX_MUTEX_H

struct mutex { unsigned int state; };

void mutex_init(struct mutex *lock);
void mutex_lock(struct mutex *lock);
int mutex_trylock(struct mutex *lock);
void mutex_unlock(struct mutex *lock);
int mutex_is_locked(struct mutex *lock);

#endif
