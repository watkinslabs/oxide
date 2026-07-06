#ifndef OXIDE_LINUX_LOCKDEP_H
#define OXIDE_LINUX_LOCKDEP_H

struct lock_class_key { unsigned long key; };

void lockdep_set_class(void *lock, struct lock_class_key *key);
void lockdep_set_class_and_name(void *lock, struct lock_class_key *key, const char *name);

#endif
