/* /bin/tkill_probe — self-signal (raise/tkill) delivery smoke.
 *
 * musl raise(sig) = tkill(gettid(), sig); abort()/pthread_kill ride the same
 * path. This was BROKEN: tkill→sys_kill resolved the target via
 * lookup_in_ns(0, tid) which only matched the opaque INTERNAL tid, while
 * gettid() returns the small vtid → ESRCH → the signal was never posted, so
 * the handler never ran (verified). Fixed by also resolving vtid/vtgid in
 * init-NS lookup. This probe raises SIGUSR1 at itself and asserts the
 * SA_SIGINFO handler ran with the right signal. */
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static volatile sig_atomic_t got;
static volatile int si_signo;
static void handler(int sig, siginfo_t *si, void *uc) {
    (void)sig; (void)uc;
    si_signo = si ? si->si_signo : -1;
    got = 1;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = handler;
    sa.sa_flags     = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, (void *)0) != 0) { printf("tkill_probe: FAIL sigaction\n"); return 1; }
    raise(SIGUSR1);                 /* tkill(gettid(), SIGUSR1) */
    /* oxide delivers pending signals at syscall-return → nanosleep windows. */
    struct timespec ts = { 0, 20 * 1000 * 1000 };
    for (int i = 0; i < 100 && !got; i++) nanosleep(&ts, (void *)0);
    if (!got)                { printf("tkill_probe: FAIL nohandler (self-signal not delivered)\n"); return 1; }
    if (si_signo != SIGUSR1) { printf("tkill_probe: FAIL siginfo=%d\n", si_signo); return 1; }
    printf("tkill_probe: PASS\n");
    return 0;
}
