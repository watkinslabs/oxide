/* C11 <threads.h>: thrd/mtx/cnd/tss/call_once over the pthread surface. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <threads.h>

static mtx_t lock;
static long counter;
static once_flag of = ONCE_FLAG_INIT;
static int once_count;
static void init_once(void) { once_count++; }

static int worker(void *arg) {
    int n = (int)(intptr_t)arg;
    for (int i = 0; i < 1000; i++) { mtx_lock(&lock); counter += n; mtx_unlock(&lock); }
    return n;
}

static cnd_t cv; static mtx_t cm; static int ready;
static int signaller(void *a) {
    (void)a;
    mtx_lock(&cm); ready = 1; cnd_signal(&cv); mtx_unlock(&cm);
    return 0;
}

int main(void) {
    call_once(&of, init_once);
    call_once(&of, init_once);
    call_once(&of, init_once);
    printf("call_once=%d\n", once_count); /* 1 */

    mtx_init(&lock, mtx_plain);
    thrd_t t[4]; int res[4] = {0};
    for (int i = 0; i < 4; i++) thrd_create(&t[i], worker, (void*)(intptr_t)(i + 1));
    int allok = 1;
    for (int i = 0; i < 4; i++) { allok &= (thrd_join(t[i], &res[i]) == thrd_success); }
    printf("counter=%ld join_ok=%d res_sum=%d\n", counter, allok, res[0]+res[1]+res[2]+res[3]);
    /* counter = 1000*(1+2+3+4)=10000; res_sum = 1+2+3+4 = 10 */
    mtx_destroy(&lock);

    tss_t k; tss_create(&k, NULL);
    tss_set(k, (void*)0x1234);
    printf("tss=%d\n", tss_get(k) == (void*)0x1234);
    tss_delete(k);

    cnd_init(&cv); mtx_init(&cm, mtx_plain);
    mtx_lock(&cm);
    thrd_t s; thrd_create(&s, signaller, NULL);
    while (!ready) cnd_wait(&cv, &cm);
    mtx_unlock(&cm);
    thrd_join(s, NULL);
    printf("cnd_ready=%d\n", ready);
    cnd_destroy(&cv); mtx_destroy(&cm);

    printf("equal=%d\n", thrd_equal(thrd_current(), thrd_current()));
    return 0;
}
