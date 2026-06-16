/* pthread_attr_* extended accessors: set/get roundtrip vs host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>

int main(void) {
    pthread_attr_t a; pthread_attr_init(&a);

    pthread_attr_setinheritsched(&a, PTHREAD_EXPLICIT_SCHED);
    int ish = -1; pthread_attr_getinheritsched(&a, &ish);
    printf("inheritsched=%d\n", ish == PTHREAD_EXPLICIT_SCHED);

    pthread_attr_setschedpolicy(&a, SCHED_FIFO);
    int pol = -1; pthread_attr_getschedpolicy(&a, &pol);
    printf("schedpolicy=%d\n", pol == SCHED_FIFO);

    struct sched_param sp = { .sched_priority = 17 };
    pthread_attr_setschedparam(&a, &sp);
    struct sched_param sp2; sp2.sched_priority = 0;
    pthread_attr_getschedparam(&a, &sp2);
    printf("schedparam=%d\n", sp2.sched_priority == 17);

    int sc = pthread_attr_setscope(&a, PTHREAD_SCOPE_SYSTEM);
    int sc_proc = pthread_attr_setscope(&a, PTHREAD_SCOPE_PROCESS);
    int gsc = -1; pthread_attr_getscope(&a, &gsc);
    printf("scope_sys=%d scope_proc_unsup=%d getscope=%d\n",
           sc == 0, sc_proc != 0, gsc == PTHREAD_SCOPE_SYSTEM);

    char stk[262144];
    pthread_attr_setstack(&a, stk, sizeof stk);
    void *sa; size_t ss;
    pthread_attr_getstack(&a, &sa, &ss);
    printf("stack=%d\n", sa == stk && ss == sizeof stk);

    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0, &cs); CPU_SET(1, &cs);
    pthread_attr_setaffinity_np(&a, sizeof cs, &cs);
    cpu_set_t cs2; CPU_ZERO(&cs2);
    pthread_attr_getaffinity_np(&a, sizeof cs2, &cs2);
    printf("affinity=%d\n", CPU_ISSET(0,&cs2) && CPU_ISSET(1,&cs2) && !CPU_ISSET(2,&cs2));

    sigset_t m; sigemptyset(&m); sigaddset(&m, SIGUSR1);
    pthread_attr_setsigmask_np(&a, &m);
    sigset_t m2; memset(&m2, 0, sizeof m2);
    int gsm = pthread_attr_getsigmask_np(&a, &m2);
    printf("sigmask=%d\n", gsm == 0 && sigismember(&m2, SIGUSR1));

    pthread_attr_destroy(&a);
    return 0;
}
