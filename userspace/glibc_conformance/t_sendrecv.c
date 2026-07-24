/* Linux rows 44/45 sendto/recvfrom corpus; compared verbatim by N. */
#define _GNU_SOURCE
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void r(const char *label, long rc) {
    printf("%s rc=%ld errno=%d\n", label, rc < 0 ? -1 : rc, rc < 0 ? errno : 0);
}

/* A bound UDP socket pair: send a datagram and receive it, checking bytes,
   source address recovery, MSG_TRUNC, and MSG_PEEK. */
static void udp_roundtrip(void) {
    int a = socket(AF_INET, SOCK_DGRAM, 0);
    int b = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in aa, ba;
    socklen_t al = sizeof(aa), bl = sizeof(ba);
    memset(&aa, 0, sizeof(aa)); memset(&ba, 0, sizeof(ba));
    aa.sin_family = ba.sin_family = AF_INET;
    aa.sin_addr.s_addr = ba.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (a < 0 || b < 0 || bind(a, (struct sockaddr *)&aa, sizeof(aa)) != 0
        || bind(b, (struct sockaddr *)&ba, sizeof(ba)) != 0
        || getsockname(a, (struct sockaddr *)&aa, &al) != 0
        || getsockname(b, (struct sockaddr *)&ba, &bl) != 0) {
        puts("udp=setup_failed"); return;
    }
    /* a -> b: "hello" */
    ssize_t s = sendto(a, "hello", 5, 0, (struct sockaddr *)&ba, sizeof(ba));
    r("sendto", s);

    /* Peek without consuming. */
    char buf[8];
    struct sockaddr_in from;
    socklen_t fl = sizeof(from);
    memset(buf, 0, sizeof(buf));
    ssize_t p = recvfrom(b, buf, sizeof(buf), MSG_PEEK, (struct sockaddr *)&from, &fl);
    printf("peek n=%zd data=%.5s from_is_a=%d\n", p, buf,
        from.sin_port == aa.sin_port);

    /* Real receive consumes; a short buffer with MSG_TRUNC reports the true
       datagram length while copying only what fits. */
    memset(buf, 0, sizeof(buf));
    fl = sizeof(from);
    ssize_t n = recvfrom(b, buf, 3, MSG_TRUNC, (struct sockaddr *)&from, &fl);
    printf("recv_trunc n=%zd data=%.3s\n", n, buf);

    /* A nonblocking receive on the now-empty socket returns EAGAIN. */
    errno = 0;
    ssize_t e = recvfrom(b, buf, sizeof(buf), MSG_DONTWAIT, NULL, NULL);
    r("recv_empty_dontwait", e);
    close(a); close(b);
}

int main(void) {
    /* sendto on an unconnected UDP socket with no destination:
       EDESTADDRREQ. */
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    errno = 0; r("sendto_no_dest", sendto(u, "x", 1, 0, NULL, 0));
    close(u);

    /* recvfrom bad fd: EBADF. */
    char b[4];
    errno = 0; r("recvfrom_badfd", recvfrom(-1, b, sizeof(b), 0, NULL, NULL));
    /* sendto bad fd: EBADF. */
    errno = 0; r("sendto_badfd", sendto(-1, "x", 1, 0, NULL, 0));

    udp_roundtrip();
    return 0;
}
