/* ucontext coroutine + legacy signal helpers vs host glibc.
 * - getcontext + makecontext a coroutine on a malloc'd stack; it increments a
 *   global and returns via uc_link. swapcontext into it and back; print the
 *   global + ordering markers.
 * - siginterrupt return; sigsetmask/sigblock round-trip on the int mask;
 *   psignal captured stderr -> pipe -> stdout. Deterministic. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <ucontext.h>

static ucontext_t uctx_main, uctx_co;
static int g;

static void coroutine(int add) {
    g += add;          /* prove the arg + stack were set up */
    g += 1;
    /* returns -> uc_link (uctx_main) */
}

int main(void) {
    /* ---- ucontext coroutine ---- */
    char *stk = malloc(64 * 1024);
    if (getcontext(&uctx_co) == -1) { perror("getcontext"); return 1; }
    uctx_co.uc_stack.ss_sp = stk;
    uctx_co.uc_stack.ss_size = 64 * 1024;
    uctx_co.uc_link = &uctx_main;
    makecontext(&uctx_co, (void (*)(void))coroutine, 1, 41);

    g = 0;
    printf("before g=%d\n", g);
    if (swapcontext(&uctx_main, &uctx_co) == -1) { perror("swapcontext"); return 1; }
    printf("after g=%d\n", g);   /* 41 + 1 = 42 */
    free(stk);

    /* ---- legacy signal: sigsetmask / sigblock round-trip ---- */
    int old = sigsetmask(0);              /* clear, get prior */
    int prev = sigblock(sigmask(SIGUSR1)); /* block USR1 */
    int now = sigblock(0);                 /* read current */
    printf("blockmask usr1=%d set=%d\n",
           (now & sigmask(SIGUSR1)) != 0, (prev & sigmask(SIGUSR1)) == 0);
    sigsetmask(old);                       /* restore */

    /* ---- siginterrupt return value ---- */
    printf("siginterrupt=%d\n", siginterrupt(SIGUSR2, 1));

    /* ---- psignal to stderr, captured via pipe -> stdout ---- */
    fflush(stderr);
    int p[2]; pipe(p);
    int saved = dup(2);
    dup2(p[1], 2);
    psignal(SIGINT, "myprog");
    fflush(stderr);
    dup2(saved, 2); close(saved); close(p[1]);
    char buf[128];
    ssize_t n = read(p[0], buf, sizeof buf - 1);
    if (n < 0) n = 0;
    buf[n] = 0;
    close(p[0]);
    printf("psignal=%s", buf);
    return 0;
}
