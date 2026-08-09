/* Linux row-50 listen(2) corpus; output is compared verbatim by N14. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void r(const char *label, int rc) {
    printf("%s rc=%d errno=%d\n", label, rc < 0 ? -1 : 0, rc < 0 ? errno : 0);
}

static int bound_stream(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd >= 0 && bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) { close(fd); return -1; }
    return fd;
}

int main(void) {
    /* Datagram and raw inet sockets: Linux sock_no_listen -> EOPNOTSUPP,
       distinct from the stream socket's EINVAL for a bad state. */
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    errno = 0; r("udp_listen", listen(u, 5));
    close(u);

    int u6 = socket(AF_INET6, SOCK_DGRAM, 0);
    errno = 0; r("udp6_listen", listen(u6, 5));
    close(u6);

    /* AF_UNIX datagram: Linux unix_listen -> EOPNOTSUPP. */
    int ud = socket(AF_UNIX, SOCK_DGRAM, 0);
    errno = 0; r("unix_dgram_listen", listen(ud, 5));
    close(ud);

    /* A bound stream socket accepts listen, and a negative backlog is clamped
       (not an error). Re-listen updates the backlog and still succeeds. A
       zero backlog is likewise accepted, not an error. A backlog far above
       net.core.somaxconn is silently clamped by __sys_listen, not refused. */
    int s = bound_stream();
    if (s >= 0) {
        errno = 0; r("stream_listen", listen(s, 5));
        errno = 0; r("stream_relisten_neg", listen(s, -1));
        errno = 0; r("stream_relisten_zero", listen(s, 0));
        errno = 0; r("stream_relisten_huge", listen(s, 1000000));
        close(s);
    }

    /* listen on an unbound stream socket auto-binds and succeeds on Linux. */
    int s2 = socket(AF_INET, SOCK_STREAM, 0);
    errno = 0; r("stream_unbound_listen", listen(s2, 5));
    close(s2);

    /* listen on a connected stream socket: Linux inet_listen requires
       sock->state == SS_UNCONNECTED, so an established (or connecting)
       socket is EINVAL, not silently accepted. */
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in la;
    memset(&la, 0, sizeof(la));
    la.sin_family = AF_INET;
    la.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int connected_ok = -1;
    if (lfd >= 0 && bind(lfd, (struct sockaddr *)&la, sizeof(la)) == 0) {
        socklen_t la_len = sizeof(la);
        if (getsockname(lfd, (struct sockaddr *)&la, &la_len) == 0 && listen(lfd, 5) == 0) {
            int cfd = socket(AF_INET, SOCK_STREAM, 0);
            if (cfd >= 0 && connect(cfd, (struct sockaddr *)&la, sizeof(la)) == 0) {
                connected_ok = cfd;
            } else if (cfd >= 0) {
                close(cfd);
            }
        }
    }
    if (connected_ok >= 0) {
        errno = 0; r("stream_connected_listen", listen(connected_ok, 5));
        close(connected_ok);
    } else {
        printf("stream_connected_listen skip=1\n");
    }
    close(lfd);

    /* Bad fd. */
    errno = 0; r("badfd", listen(-1, 5));

    /* A valid fd that is not a socket is ENOTSOCK, not EBADF. */
    int file = open("/dev/null", O_RDONLY);
    errno = 0; r("regular_file", listen(file, 5));
    close(file);
    return 0;
}
