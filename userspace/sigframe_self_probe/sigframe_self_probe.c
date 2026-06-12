/* /bin/sigframe_self_probe — self-contained rt_sigframe acceptance test.
 *
 * Resolves the "minimal arm signal frame" question (project_signal_frame_
 * minimal) without a tty ^C injection. Uses alarm(2)/SIGALRM — a proven-
 * working kernel-posted delivery (cf. alarm_probe) — with an SA_SIGINFO
 * handler, and checks the kernel delivered a REAL Linux rt_sigframe:
 *   - handler invoked as handler(sig, &siginfo, &ucontext),
 *   - siginfo->si_signo correct, ucontext pointer non-NULL,
 *   - rt_sigreturn resumed (we reach the check after the handler).
 * Minimal frame (sig-only) → FAIL/crash; full frame → "...: PASS".
 * Arch-portable (x86_64 + aarch64). */
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t got;
static volatile int si_signo;
static volatile int uc_nonnull;
static volatile int handler_sig;

static void handler(int sig, siginfo_t *si, void *uc) {
    handler_sig = sig;
    si_signo    = si ? si->si_signo : -1;
    uc_nonnull  = uc ? 1 : 0;
    got = 1;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = handler;
    sa.sa_flags     = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGALRM, &sa, (void *)0) != 0) {
        printf("sigframe_self_probe: FAIL sigaction\n"); return 1;
    }
    alarm(1);                       /* kernel posts SIGALRM in ~1s */
    /* oxide delivers pending signals at syscall-return → nanosleep windows. */
    struct timespec ts = { 0, 20 * 1000 * 1000 };   /* 20 ms */
    for (int i = 0; i < 200 && !got; i++) nanosleep(&ts, (void *)0);
    if (!got)                       { printf("sigframe_self_probe: FAIL nohandler\n"); return 1; }
    if (handler_sig != SIGALRM)     { printf("sigframe_self_probe: FAIL sig=%d\n", handler_sig); return 1; }
    if (si_signo != SIGALRM)        { printf("sigframe_self_probe: FAIL siginfo=%d\n", si_signo); return 1; }
    if (!uc_nonnull)                { printf("sigframe_self_probe: FAIL noucontext\n"); return 1; }
    printf("sigframe_self_probe: PASS\n");
    return 0;
}
