/* poll/ppoll: a ready pipe fd reports POLLIN; an empty pipe times out (0). */
#define _GNU_SOURCE
#include <stdio.h>
#include <poll.h>
#include <unistd.h>
#include <time.h>
#include <string.h>

int main(void) {
    int p[2];
    if (pipe(p) != 0) { printf("pipe fail\n"); return 1; }

    struct pollfd pf = { .fd = p[0], .events = POLLIN, .revents = 0 };
    int n = poll(&pf, 1, 10);                 /* empty → timeout */
    printf("empty=%d revents=%d\n", n, pf.revents);

    if (write(p[1], "x", 1) != 1) { printf("write fail\n"); return 1; }
    pf.revents = 0;
    n = poll(&pf, 1, 100);                     /* ready → POLLIN */
    printf("ready=%d in=%d\n", n, (pf.revents & POLLIN) ? 1 : 0);

    struct timespec ts = { 0, 100*1000*1000 }; /* 100ms */
    pf.revents = 0;
    n = ppoll(&pf, 1, &ts, NULL);
    printf("ppoll=%d in=%d\n", n, (pf.revents & POLLIN) ? 1 : 0);
    return 0;
}
