#ifndef OXIDE_LINUX_SPINLOCK_H
#define OXIDE_LINUX_SPINLOCK_H

typedef struct { unsigned int state; } spinlock_t;
typedef spinlock_t raw_spinlock_t;

void spin_lock_init(spinlock_t *lock);
void spin_lock(spinlock_t *lock);
int spin_trylock(spinlock_t *lock);
void spin_unlock(spinlock_t *lock);
int spin_is_locked(spinlock_t *lock);
void raw_spin_lock_init(raw_spinlock_t *lock);
void raw_spin_lock(raw_spinlock_t *lock);
int raw_spin_trylock(raw_spinlock_t *lock);
void raw_spin_unlock(raw_spinlock_t *lock);
void _raw_spin_lock(raw_spinlock_t *lock);
void _raw_spin_unlock(raw_spinlock_t *lock);
void _raw_spin_lock_bh(raw_spinlock_t *lock);
void _raw_spin_lock_irq(raw_spinlock_t *lock);
unsigned long _raw_spin_lock_irqsave(raw_spinlock_t *lock);
void _raw_spin_unlock_bh(raw_spinlock_t *lock);
void _raw_spin_unlock_irq(raw_spinlock_t *lock);
void _raw_spin_unlock_irqrestore(raw_spinlock_t *lock, unsigned long flags);

#endif
