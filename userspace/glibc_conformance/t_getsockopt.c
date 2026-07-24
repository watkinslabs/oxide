/* Linux row-55 getsockopt(2) corpus; compared verbatim by N18. */
#define _GNU_SOURCE
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

static void show(const char *label, int fd, int level, int opt) {
    int val = -1;
    socklen_t len = sizeof(val);
    errno = 0;
    int rc = getsockopt(fd, level, opt, &val, &len);
    if (rc != 0) { printf("%s rc=-1 errno=%d\n", label, errno); return; }
    printf("%s rc=0 val=%d len=%u\n", label, val, (unsigned)len);
}

int main(void) {
    int t = socket(AF_INET, SOCK_STREAM, 0);
    int u = socket(AF_INET, SOCK_DGRAM, 0);

    /* SO_TYPE / SO_DOMAIN / SO_PROTOCOL / SO_ACCEPTCONN readback. */
    show("tcp_type", t, SOL_SOCKET, SO_TYPE);
    show("udp_type", u, SOL_SOCKET, SO_TYPE);
    show("tcp_domain", t, SOL_SOCKET, SO_DOMAIN);
    show("tcp_protocol", t, SOL_SOCKET, SO_PROTOCOL);
    show("tcp_acceptconn", t, SOL_SOCKET, SO_ACCEPTCONN);

    /* SO_ERROR with no pending error is 0. */
    show("tcp_soerror", t, SOL_SOCKET, SO_ERROR);

    /* Default SO_REUSEADDR / SO_KEEPALIVE are 0. */
    show("tcp_reuseaddr", t, SOL_SOCKET, SO_REUSEADDR);
    show("tcp_keepalive", t, SOL_SOCKET, SO_KEEPALIVE);

    /* Set then read back SO_REUSEADDR. */
    int one = 1;
    setsockopt(t, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    show("tcp_reuseaddr_set", t, SOL_SOCKET, SO_REUSEADDR);

    /* SO_RCVBUF/SO_SNDBUF return a (doubled) positive value. */
    {
        int val = -1; socklen_t len = sizeof(val);
        errno = 0;
        int rc = getsockopt(t, SOL_SOCKET, SO_RCVBUF, &val, &len);
        printf("tcp_rcvbuf rc=%d positive=%d len=%u\n", rc, rc == 0 && val > 0, (unsigned)len);
    }

    /* getsockopt with a NULL optlen pointer is EFAULT. */
    {
        int val = 0;
        errno = 0;
        int rc = getsockopt(t, SOL_SOCKET, SO_TYPE, &val, NULL);
        printf("null_optlen rc=%d errno=%d\n", rc, rc < 0 ? errno : 0);
    }

    /* Unknown option / unknown level: ENOPROTOOPT. */
    show("unknown_opt", t, SOL_SOCKET, 99999);
    show("unknown_level", t, 999, 1);

    /* Bad fd. */
    show("badfd", -1, SOL_SOCKET, SO_TYPE);

    close(t); close(u);
    return 0;
}
