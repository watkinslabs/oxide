/* pthread barriers + spinlocks. 4 threads each spin-lock-increment a shared
 * counter N times, then rendezvous at a barrier. Exactly one waiter gets
 * PTHREAD_BARRIER_SERIAL_THREAD. Deterministic output vs host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <pthread.h>

#define T 4
#define N 10000

static pthread_spinlock_t lock;
static pthread_barrier_t bar;
static long counter;
static int serials;

void *worker(void *arg) {
    (void)arg;
    for (int i = 0; i < N; i++) {
        pthread_spin_lock(&lock);
        counter++;
        pthread_spin_unlock(&lock);
    }
    int r = pthread_barrier_wait(&bar);
    if (r == PTHREAD_BARRIER_SERIAL_THREAD) {
        pthread_spin_lock(&lock);
        serials++;
        pthread_spin_unlock(&lock);
    }
    return NULL;
}

int main(void) {
    pthread_spin_init(&lock, 0);
    printf("barrier_init=%d\n", pthread_barrier_init(&bar, NULL, T));
    pthread_t th[T];
    for (int i = 0; i < T; i++) pthread_create(&th[i], NULL, worker, NULL);
    for (int i = 0; i < T; i++) pthread_join(th[i], NULL);
    printf("counter=%ld\n", counter);     /* T*N = 40000 */
    printf("serials=%d\n", serials);       /* exactly 1 */
    printf("trylock_free=%d\n", pthread_spin_trylock(&lock)); /* 0 (got it) */
    printf("trylock_busy=%d\n", pthread_spin_trylock(&lock) != 0); /* 1 (EBUSY) */
    pthread_spin_unlock(&lock);
    pthread_barrier_destroy(&bar);
    pthread_spin_destroy(&lock);
    return 0;
}
