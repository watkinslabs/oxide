/* Linux row-50 listen(2) corpus; output is compared verbatim by N14. */
#define _GNU_SOURCE
#include <errno.h>
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
       (not an error). Re-listen updates the backlog and still succeeds. */
    int s = bound_stream();
    if (s >= 0) {
        errno = 0; r("stream_listen", listen(s, 5));
        errno = 0; r("stream_relisten_neg", listen(s, -1));
        close(s);
    }

    /* listen on an unbound stream socket auto-binds and succeeds on Linux. */
    int s2 = socket(AF_INET, SOCK_STREAM, 0);
    errno = 0; r("stream_unbound_listen", listen(s2, 5));
    close(s2);

    /* Bad fd. */
    errno = 0; r("badfd", listen(-1, 5));
    return 0;
}
