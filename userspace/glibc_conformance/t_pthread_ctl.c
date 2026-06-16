/* pthread thread-control + scheduling. Compare vs host glibc. Avoid printing
 * tid/clockid raw values (differ per-process); print derived booleans/names. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <time.h>

int main(void) {
    pthread_t self = pthread_self();

    printf("kill0=%d\n", pthread_kill(self, 0)); /* existence -> 0 */
    printf("yield=%d\n", pthread_yield());

    pthread_setname_np(self, "worker");
    char nm[16] = {0};
    pthread_getname_np(self, nm, sizeof nm);
    printf("name=%s\n", nm);

    clockid_t clk;
    int gcc = pthread_getcpuclockid(self, &clk);
    struct timespec ts;
    printf("getcpuclockid=%d clock_ok=%d\n", gcc, clock_gettime(clk, &ts) == 0);

    int policy = -1; struct sched_param sp;
    int gsp = pthread_getschedparam(self, &policy, &sp);
    printf("getschedparam=%d policy_other=%d prio0=%d\n",
           gsp, policy == SCHED_OTHER, sp.sched_priority == 0);

    cpu_set_t cs; CPU_ZERO(&cs);
    int gaff = pthread_getaffinity_np(self, sizeof cs, &cs);
    printf("getaffinity=%d cpus_ge1=%d\n", gaff, CPU_COUNT(&cs) >= 1);

    printf("setconc=%d getconc=%d\n", pthread_setconcurrency(3), pthread_getconcurrency());

    /* sigqueue to self via pthread_sigqueue, receive the value */
    sigset_t set; sigemptyset(&set); sigaddset(&set, SIGRTMIN);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    union sigval v; v.sival_int = 4242;
    int sq = pthread_sigqueue(self, SIGRTMIN, v);
    siginfo_t si; struct timespec to = {1, 0};
    int got = sigtimedwait(&set, &si, &to);
    printf("sigqueue=%d got_signo=%d got_val=%d\n", sq, got == SIGRTMIN, si.si_value.sival_int);
    return 0;
}
