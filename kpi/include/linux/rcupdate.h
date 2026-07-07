#ifndef OXIDE_LINUX_RCUPDATE_H
#define OXIDE_LINUX_RCUPDATE_H

void __rcu_read_lock(void);
void __rcu_read_unlock(void);
void synchronize_rcu(void);
void rcu_barrier(void);

#endif
