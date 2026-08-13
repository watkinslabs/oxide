#ifndef OXIDE_LINUX_RCUPDATE_H
#define OXIDE_LINUX_RCUPDATE_H

void __rcu_read_lock(void);
void __rcu_read_unlock(void);
void synchronize_rcu(void);
void rcu_barrier(void);

struct rcu_head {
    struct rcu_head *next;
    void (*func)(struct rcu_head *head);
};

#endif
