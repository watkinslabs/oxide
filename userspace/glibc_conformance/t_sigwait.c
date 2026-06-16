/* sigwait/sigtimedwait/pthread_sigmask: block SIGUSR1, raise it, sigwait
 * accepts it; sigtimedwait with a short timeout on an empty set → EAGAIN. */
#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <string.h>

int main(void) {
    sigset_t set; sigemptyset(&set); sigaddset(&set, SIGUSR1);
    printf("mask=%d\n", pthread_sigmask(SIG_BLOCK, &set, NULL));

    raise(SIGUSR1);
    int got = 0;
    printf("sigwait=%d sig=%d\n", sigwait(&set, &got), got);

    /* empty wait set + tiny timeout → -1/EAGAIN */
    sigset_t empty; sigemptyset(&empty);
    struct timespec ts = { 0, 1000*1000 };
    int r = sigtimedwait(&empty, NULL, &ts);
    printf("timedwait=%d eagain=%d\n", r, (r < 0 && errno == EAGAIN) ? 1 : 0);
    return 0;
}
