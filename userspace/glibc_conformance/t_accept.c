/* Linux rows 43/288 accept/accept4 corpus; compared verbatim by N. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void r(const char *label, int rc) {
    printf("%s rc=%d errno=%d\n", label, rc < 0 ? -1 : 0, rc < 0 ? errno : 0);
}

static int listener(struct sockaddr_in *addr) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    socklen_t len = sizeof(*addr);
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || bind(fd, (struct sockaddr *)addr, sizeof(*addr)) != 0
        || listen(fd, 4) != 0
        || getsockname(fd, (struct sockaddr *)addr, &len) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    return fd;
}

int main(void) {
    struct sockaddr_in addr;
    int l = listener(&addr);
    if (l < 0) { puts("setup=failed"); return 0; }

    /* accept4 with an invalid flag bit: Linux __sys_accept4_file rejects
       anything outside SOCK_CLOEXEC|SOCK_NONBLOCK with EINVAL, and this is
       checked before the blocking wait. */
    errno = 0; r("accept4_badflag", accept4(l, NULL, NULL, 0x40));

    /* accept on a non-listening (freshly created) socket: EINVAL. */
    int notlisten = socket(AF_INET, SOCK_STREAM, 0);
    errno = 0; r("accept_nonlisten", accept(notlisten, NULL, NULL));
    close(notlisten);

    /* accept on a UDP socket: EOPNOTSUPP (sock has no accept op). */
    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    errno = 0; r("accept_udp", accept(udp, NULL, NULL));
    close(udp);

    /* Bad fd. */
    errno = 0; r("accept_badfd", accept(-1, NULL, NULL));

    /* A real connection: accept returns a fd; the accepted fd's CLOEXEC and
       NONBLOCK come only from accept4 flags, never inherited from the
       listener. Establish a client first. */
    int c = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(c, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        puts("connect=failed"); close(c); close(l); return 0;
    }
    struct sockaddr_in peer;
    socklen_t plen = sizeof(peer);
    int s = accept4(l, (struct sockaddr *)&peer, &plen, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (s < 0) { r("accept_conn", s); close(c); close(l); return 0; }
    int fdflags = fcntl(s, F_GETFD);
    int status = fcntl(s, F_GETFL);
    printf("accepted cloexec=%d nonblock=%d peer_family=%d peer_len=%u\n",
        fdflags >= 0 && (fdflags & FD_CLOEXEC) ? 1 : 0,
        status >= 0 && (status & O_NONBLOCK) ? 1 : 0,
        peer.sin_family, (unsigned)plen);

    /* A plain accept (no flags) yields a blocking, non-cloexec fd. */
    int c2 = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(c2, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        int s2 = accept(l, NULL, NULL);
        if (s2 >= 0) {
            int f2 = fcntl(s2, F_GETFD);
            int st2 = fcntl(s2, F_GETFL);
            printf("plain_accept cloexec=%d nonblock=%d\n",
                f2 >= 0 && (f2 & FD_CLOEXEC) ? 1 : 0,
                st2 >= 0 && (st2 & O_NONBLOCK) ? 1 : 0);
            close(s2);
        }
        close(c2);
    }
    close(s); close(c); close(l);
    return 0;
}
