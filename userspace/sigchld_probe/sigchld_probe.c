/* /bin/sigchld_probe — B117 acceptance test for Linux-correct SIGCHLD
 * siginfo. An SA_SIGINFO SIGCHLD handler MUST read the real
 * si_pid/si_status/si_code for the child that exited (siginfo(7)):
 *   - si_signo == SIGCHLD,
 *   - si_code  == CLD_EXITED (1)  for a normal _exit(),
 *   - si_status == the child's exit code,
 *   - si_pid   == the value fork() returned (the child's VPID).
 * Pre-B117 the kernel only set the parent's SIGCHLD pending bit and
 * queued NO siginfo, so si_pid/si_status/si_code came back 0/garbage
 * and real reapers that switch on si_pid broke.
 *
 * Delivery is at syscall-return → we spin a nanosleep loop so the
 * kernel has a syscall window to build the handler frame.
 * Arch-portable (x86_64 + aarch64). */
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>

#define CHILD_EXIT_CODE 42

static volatile sig_atomic_t got;
static volatile int h_signo;
static volatile int h_code;
static volatile int h_status;
static volatile int h_pid;

static void handler(int sig, siginfo_t *si, void *uc) {
    (void)uc;
    h_signo  = si ? si->si_signo  : -1;
    h_code   = si ? si->si_code   : -1;
    h_status = si ? si->si_status : -1;
    h_pid    = si ? si->si_pid    : -1;
    (void)sig;
    got = 1;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = handler;
    sa.sa_flags     = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGCHLD, &sa, (void *)0) != 0) {
        printf("sigchld_probe: FAIL sigaction\n"); return 1;
    }

    pid_t kid = fork();
    if (kid < 0) { printf("sigchld_probe: FAIL fork\n"); return 1; }
    if (kid == 0) {
        _exit(CHILD_EXIT_CODE);     /* child: exit with a known code */
    }

    /* Parent: wait for the SA_SIGINFO handler to fire. Delivery is at
     * a syscall-return tail, so the nanosleep loop gives it windows. */
    struct timespec ts = { 0, 20 * 1000 * 1000 };   /* 20 ms */
    for (int i = 0; i < 200 && !got; i++) nanosleep(&ts, (void *)0);

    /* Reap so we don't leave a zombie regardless of pass/fail. */
    int wstat = 0;
    waitpid(kid, &wstat, 0);

    if (!got)               { printf("sigchld_probe: FAIL nohandler\n"); return 1; }
    if (h_signo != SIGCHLD) { printf("sigchld_probe: FAIL si_signo=%d\n", h_signo); return 1; }
    if (h_code != CLD_EXITED) { printf("sigchld_probe: FAIL si_code=%d (want %d)\n", h_code, CLD_EXITED); return 1; }
    if (h_status != CHILD_EXIT_CODE) { printf("sigchld_probe: FAIL si_status=%d (want %d)\n", h_status, CHILD_EXIT_CODE); return 1; }
    if (h_pid != (int)kid)  { printf("sigchld_probe: FAIL si_pid=%d (want %d)\n", h_pid, (int)kid); return 1; }

    printf("sigchld_probe: PASS\n");
    return 0;
}
