/* SysV signal: sighold/sigrelse/sigignore/sigset over sigprocmask/sigaction. vs host. */
#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
int blocked(int sig) { sigset_t s; sigprocmask(SIG_BLOCK, NULL, &s); return sigismember(&s, sig); }
int main(void) {
    sighold(SIGUSR1);
    printf("held=%d\n", blocked(SIGUSR1));
    sigrelse(SIGUSR1);
    printf("released=%d\n", blocked(SIGUSR1) == 0);
    sigignore(SIGUSR2);
    struct sigaction sa; sigaction(SIGUSR2, NULL, &sa);
    printf("ignored=%d\n", sa.sa_handler == SIG_IGN);
    /* sigset: SIGUSR1 currently unblocked + SIG_DFL -> SIG_HOLD returns prior (SIG_DFL=0) */
    void *p1 = sigset(SIGUSR1, SIG_HOLD);
    printf("sigset_prev_dfl=%d held_now=%d\n", p1 == SIG_DFL, blocked(SIGUSR1));
    /* now held -> sigset SIG_HOLD again returns SIG_HOLD(2) */
    void *p2 = sigset(SIGUSR1, SIG_HOLD);
    printf("sigset_prev_hold=%d\n", p2 == SIG_HOLD);
    return 0;
}
