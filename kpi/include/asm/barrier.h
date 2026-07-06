#ifndef OXIDE_ASM_BARRIER_H
#define OXIDE_ASM_BARRIER_H

#define barrier() __asm__ __volatile__("" ::: "memory")
#define mb() __sync_synchronize()
#define rmb() mb()
#define wmb() mb()
#define smp_mb() mb()
#define smp_rmb() rmb()
#define smp_wmb() wmb()

#endif
