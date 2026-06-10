/* SA_SIGINFO signal-frame acceptance probe — tty SIGINT (the lazygit ^C case).
 * Verifies the kernel delivers a real Linux rt_sigframe: handler invoked as
 * handler(sig,&siginfo,&ucontext) with valid siginfo + non-NULL ucontext, and
 * rt_sigreturn resumes main(). Old minimal frame → FAIL/crash; full frame →
 * SIGFRAME_OK. Arch-portable. Waits via a nanosleep loop (NOT pause/busy-wait):
 * oxide delivers signals at syscall-return, and arm pause() returns
 * immediately, so nanosleep(50ms) gives clean per-iteration delivery windows. */
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static volatile sig_atomic_t got;
static volatile int si_signo;
static volatile int uc_nonnull;

static void handler(int sig, siginfo_t *si, void *uc) {
    (void)sig;
    si_signo   = si ? si->si_signo : -1;
    uc_nonnull = uc ? 1 : 0;
    got = 1;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = handler;
    sa.sa_flags     = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, (void *)0) != 0) { printf("SIGFRAME_FAIL=sigaction\n"); return 1; }
    printf("SIGPROBE_READY\n");
    fflush(stdout);
    struct timespec ts = { 0, 50 * 1000 * 1000 };   /* 50 ms */
    for (int i = 0; i < 200 && !got; i++) nanosleep(&ts, (void *)0);   /* ^C arrives during a sleep */
    if (!got)               { printf("SIGFRAME_FAIL=nohandler\n"); return 1; }
    if (si_signo != SIGINT) { printf("SIGFRAME_FAIL=siginfo=%d\n", si_signo); return 1; }
    if (!uc_nonnull)        { printf("SIGFRAME_FAIL=noucontext\n"); return 1; }
    printf("SIGFRAME_OK\n");
    return 0;
}
