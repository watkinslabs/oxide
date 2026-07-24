/* Linux IP_TTL value validation corpus (N17). */
#define _GNU_SOURCE
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    /* -1 selects the default TTL; readback shows the default (64). */
    int v = -1;
    int rc = setsockopt(fd, IPPROTO_IP, IP_TTL, &v, sizeof(v));
    int got = -9; socklen_t l = sizeof(got);
    getsockopt(fd, IPPROTO_IP, IP_TTL, &got, &l);
    printf("ttl_neg1 rc=%d readback=%d\n", rc, got);
    /* 0 is EINVAL (modern Linux `val < 1`), as is < -1 and > 255. */
    for (int bad = -3; bad <= 0; bad++) {
        if (bad == -1) continue;
        v = bad; errno = 0;
        rc = setsockopt(fd, IPPROTO_IP, IP_TTL, &v, sizeof(v));
        printf("ttl_%d rc=%d errno=%d\n", bad, rc, rc < 0 ? errno : 0);
    }
    v = 256; errno = 0;
    rc = setsockopt(fd, IPPROTO_IP, IP_TTL, &v, sizeof(v));
    printf("ttl_256 rc=%d errno=%d\n", rc < 0 ? -1 : 0, rc < 0 ? errno : 0);
    /* A normal value round-trips. */
    v = 30; setsockopt(fd, IPPROTO_IP, IP_TTL, &v, sizeof(v));
    got = -9; l = sizeof(got); getsockopt(fd, IPPROTO_IP, IP_TTL, &got, &l);
    printf("ttl_30 readback=%d\n", got);
    close(fd);
    return 0;
}
