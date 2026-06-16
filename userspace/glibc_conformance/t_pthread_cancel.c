/* pthread cancellation + try/timed join + getattr_np vs host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>

static void *canceller(void *a) { (void)a; for (;;) pthread_testcancel(); return (void*)123; }
static void *barrierw(void *a) { pthread_barrier_wait((pthread_barrier_t*)a); return NULL; }
static void *quick(void *a) { (void)a; return NULL; }

int main(void) {
    int old = -1, old2 = -1;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old);
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &old2);
    printf("cancelstate=%d\n", old == PTHREAD_CANCEL_ENABLE && old2 == PTHREAD_CANCEL_DISABLE);
    int ot = -1, ot2 = -1;
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &ot);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &ot2);
    printf("canceltype=%d\n", ot == PTHREAD_CANCEL_DEFERRED && ot2 == PTHREAD_CANCEL_ASYNCHRONOUS);

    pthread_t tc; pthread_create(&tc, NULL, canceller, NULL);
    pthread_cancel(tc);
    void *res; pthread_join(tc, &res);
    printf("canceled=%d\n", res == PTHREAD_CANCELED);

    pthread_barrier_t b; pthread_barrier_init(&b, NULL, 2);
    pthread_t tb; pthread_create(&tb, NULL, barrierw, &b);
    void *r;
    int tj = pthread_tryjoin_np(tb, &r);   /* worker not exited -> EBUSY */
    pthread_barrier_wait(&b);              /* release worker */
    struct timespec dl; clock_gettime(CLOCK_REALTIME, &dl); dl.tv_sec += 5;
    int tmj = pthread_timedjoin_np(tb, &r, &dl);
    printf("tryjoin_ebusy=%d timedjoin=%d\n", tj == EBUSY, tmj);
    pthread_barrier_destroy(&b);

    pthread_t tg; pthread_create(&tg, NULL, quick, NULL);
    pthread_attr_t ga;
    int g = pthread_getattr_np(tg, &ga);
    void *sa = NULL; size_t ss = 0, gs = 0;
    pthread_attr_getstack(&ga, &sa, &ss);
    pthread_attr_getguardsize(&ga, &gs);
    printf("getattr=%d stack_ok=%d guard_ok=%d\n", g, ss > 0 && sa != NULL, gs > 0);
    pthread_join(tg, NULL);
    pthread_attr_destroy(&ga);
    return 0;
}
