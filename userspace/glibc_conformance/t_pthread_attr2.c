/* mutexattr/condattr/rwlockattr extended accessors + timed/clock lock variants.
 * Compare vs host glibc. Timed locks tested uncontended (deterministic 0). */
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>

int main(void) {
    pthread_mutexattr_t ma; pthread_mutexattr_init(&ma);
    pthread_mutexattr_settype(&ma, PTHREAD_MUTEX_RECURSIVE);
    int t = -1; pthread_mutexattr_gettype(&ma, &t);
    pthread_mutexattr_setprotocol(&ma, PTHREAD_PRIO_INHERIT);
    int pr = -1; pthread_mutexattr_getprotocol(&ma, &pr);
    pthread_mutexattr_setpshared(&ma, PTHREAD_PROCESS_SHARED);
    int ps = -1; pthread_mutexattr_getpshared(&ma, &ps);
    pthread_mutexattr_setrobust(&ma, PTHREAD_MUTEX_ROBUST);
    int rb = -1; pthread_mutexattr_getrobust(&ma, &rb);
    pthread_mutexattr_setprioceiling(&ma, 5);
    int pc = -1; pthread_mutexattr_getprioceiling(&ma, &pc);
    pthread_mutexattr_gettype(&ma, &t); /* survives other sets */
    printf("ma type=%d proto=%d pshared=%d robust=%d ceil=%d kept=%d\n",
           t == PTHREAD_MUTEX_RECURSIVE, pr == PTHREAD_PRIO_INHERIT,
           ps == PTHREAD_PROCESS_SHARED, rb == PTHREAD_MUTEX_ROBUST, pc == 5,
           t == PTHREAD_MUTEX_RECURSIVE);

    pthread_condattr_t ca; pthread_condattr_init(&ca);
    pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
    int clk = -1; pthread_condattr_getclock(&ca, &clk);
    pthread_condattr_setpshared(&ca, PTHREAD_PROCESS_SHARED);
    int cps = -1; pthread_condattr_getpshared(&ca, &cps);
    printf("ca clock=%d pshared=%d\n", clk == CLOCK_MONOTONIC, cps == PTHREAD_PROCESS_SHARED);

    pthread_rwlockattr_t ra; pthread_rwlockattr_init(&ra);
    pthread_rwlockattr_setkind_np(&ra, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
    int rk = -1; pthread_rwlockattr_getkind_np(&ra, &rk);
    pthread_rwlockattr_setpshared(&ra, PTHREAD_PROCESS_SHARED);
    int rps = -1; pthread_rwlockattr_getpshared(&ra, &rps);
    printf("ra kind=%d pshared=%d\n",
           rk == PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP, rps == PTHREAD_PROCESS_SHARED);

    /* timed/clock rwlock: uncontended success returns 0 on both libs */
    pthread_rwlock_t rw; pthread_rwlock_init(&rw, NULL);
    struct timespec fdl; clock_gettime(CLOCK_REALTIME, &fdl); fdl.tv_sec += 10;
    int rd = pthread_rwlock_timedrdlock(&rw, &fdl); pthread_rwlock_unlock(&rw);
    int cr = pthread_rwlock_clockrdlock(&rw, CLOCK_REALTIME, &fdl); pthread_rwlock_unlock(&rw);
    int wr = pthread_rwlock_timedwrlock(&rw, &fdl); pthread_rwlock_unlock(&rw);
    int cw2 = pthread_rwlock_clockwrlock(&rw, CLOCK_REALTIME, &fdl); pthread_rwlock_unlock(&rw);
    printf("timedrd=%d clockrd=%d timedwr=%d clockwr=%d\n", rd, cr, wr, cw2);

    pthread_mutex_t mx = PTHREAD_MUTEX_INITIALIZER;
    struct timespec fut; clock_gettime(CLOCK_MONOTONIC, &fut); fut.tv_sec += 10;
    printf("clocklock=%d\n", pthread_mutex_clocklock(&mx, CLOCK_MONOTONIC, &fut));
    pthread_mutex_unlock(&mx);

    pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
    pthread_mutex_lock(&mx);
    struct timespec past; clock_gettime(CLOCK_MONOTONIC, &past);
    int cw = pthread_cond_clockwait(&cv, &mx, CLOCK_MONOTONIC, &past);
    pthread_mutex_unlock(&mx);
    printf("cond_clockwait_to=%d\n", cw == ETIMEDOUT);
    return 0;
}
