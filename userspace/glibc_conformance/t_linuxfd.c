/* Linux event fds: eventfd counter round-trip, timerfd expiry, inotify
 * init/add/rm. Deterministic outputs to diff vs host glibc. */
#include <stdio.h>
#include <stdint.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <string.h>

int main(void) {
    /* eventfd: write 7, read back 7 */
    int ef = eventfd(0, 0);
    uint64_t v = 7; if (write(ef, &v, 8) != 8) { printf("ev write fail\n"); return 1; }
    v = 0; if (read(ef, &v, 8) != 8) { printf("ev read fail\n"); return 1; }
    printf("eventfd=%llu\n", (unsigned long long)v);
    close(ef);

    /* timerfd: 20ms one-shot, blocking read returns >=1 expiration */
    int tf = timerfd_create(CLOCK_MONOTONIC, 0);
    struct itimerspec its; memset(&its, 0, sizeof its);
    its.it_value.tv_nsec = 20*1000*1000;
    if (timerfd_settime(tf, 0, &its, NULL) != 0) { printf("tf set fail\n"); return 1; }
    uint64_t exp = 0; if (read(tf, &exp, 8) != 8) { printf("tf read fail\n"); return 1; }
    printf("timerfd_expired=%d\n", exp >= 1 ? 1 : 0);
    close(tf);

    /* inotify: init1 + add_watch(/tmp) + rm_watch */
    int in = inotify_init1(0);
    int wd = inotify_add_watch(in, "/tmp", IN_CREATE);
    printf("inotify wd_ok=%d rm=%d\n", wd >= 0 ? 1 : 0, inotify_rm_watch(in, wd) == 0 ? 1 : 0);
    close(in);
    return 0;
}
