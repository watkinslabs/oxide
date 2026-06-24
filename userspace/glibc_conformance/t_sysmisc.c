/* gnu_dev_*, swab, ftok, timespec_get, group_member, klogctl. vs host glibc. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/klog.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/ipc.h>
#include <time.h>
#include <unistd.h>
#include <grp.h>

int main(void) {
    dev_t d = gnu_dev_makedev(259, 17);
    printf("dev=%d %d\n", gnu_dev_major(d) == 259, gnu_dev_minor(d) == 17);

    char buf[5] = {0};
    swab("ABCD", buf, 4);
    printf("swab=%d\n", strcmp(buf, "BADC") == 0);

    key_t k = ftok("/tmp", 42);
    printf("ftok=%d stable=%d\n", k != -1, k == ftok("/tmp", 42));

    struct timespec ts;
    printf("timespec_get=%d sec_pos=%d\n", timespec_get(&ts, TIME_UTC), ts.tv_sec > 0);

    printf("group_member=%d\n", group_member(0x7ffffffe));  /* not a member -> 0 */
    errno = 0;
    int kr = klogctl(10, NULL, 0);
    printf("klogctl=%d errno=%d\n", kr, kr < 0 ? errno : 0);
    return 0;
}
