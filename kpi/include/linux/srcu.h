#ifndef OXIDE_LINUX_SRCU_H
#define OXIDE_LINUX_SRCU_H

#include <linux/rcupdate.h>
#include <linux/types.h>

struct srcu_ctr {
    long srcu_locks;
    long srcu_unlocks;
};

struct srcu_data;
struct srcu_usage;

struct srcu_struct {
    struct srcu_ctr *srcu_ctrp;
    struct srcu_data *sda;
    u8 srcu_reader_flavor;
    u8 __srcu_pad[7];
    struct srcu_usage *srcu_sup;
};

int init_srcu_struct(struct srcu_struct *ssp);
void cleanup_srcu_struct(struct srcu_struct *ssp);
int __srcu_read_lock(struct srcu_struct *ssp);
void __srcu_read_unlock(struct srcu_struct *ssp, int idx);
void synchronize_srcu(struct srcu_struct *ssp);
void synchronize_srcu_expedited(struct srcu_struct *ssp);

static inline int srcu_read_lock(struct srcu_struct *ssp) { return __srcu_read_lock(ssp); }
static inline void srcu_read_unlock(struct srcu_struct *ssp, int idx) { __srcu_read_unlock(ssp, idx); }
#define srcu_read_lock_held(ssp) 1
#define DEFINE_SRCU(name) struct srcu_struct name
#define DEFINE_STATIC_SRCU(name) static struct srcu_struct name

#endif
