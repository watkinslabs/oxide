/* Linux row-49 bind(2) corpus; output is compared verbatim by N13. */
#define _GNU_SOURCE
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void t(const char *label, int rc) {
    printf("%s rc=%d errno=%d\n", label, rc < 0 ? -1 : 0, rc < 0 ? errno : 0);
}

static int v4sock(void) { return socket(AF_INET, SOCK_STREAM, 0); }
static int v6sock(void) { return socket(AF_INET6, SOCK_STREAM, 0); }

int main(void) {
    struct sockaddr_in a4;
    struct sockaddr_in6 a6;
    int fd;

    /* Short addrlen for a v4 bind: Linux __inet_bind requires >= 16. */
    fd = v4sock();
    memset(&a4, 0, sizeof(a4));
    a4.sin_family = AF_INET;
    a4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    errno = 0; t("v4_len8", bind(fd, (struct sockaddr *)&a4, 8));
    errno = 0; t("v4_len15", bind(fd, (struct sockaddr *)&a4, 15));
    errno = 0; t("v4_len16", bind(fd, (struct sockaddr *)&a4, 16));
    close(fd);

    /* Short addrlen for a v6 bind: Linux inet6_bind requires >= 24. */
    fd = v6sock();
    memset(&a6, 0, sizeof(a6));
    a6.sin6_family = AF_INET6;
    a6.sin6_addr = in6addr_loopback;
    errno = 0; t("v6_len23", bind(fd, (struct sockaddr *)&a6, 23));
    errno = 0; t("v6_len24", bind(fd, (struct sockaddr *)&a6, 24));
    close(fd);

    /* Family mismatch. */
    fd = v4sock();
    memset(&a4, 0, sizeof(a4));
    a4.sin_family = AF_INET6;
    errno = 0; t("v4sock_famv6", bind(fd, (struct sockaddr *)&a4, sizeof(a4)));
    close(fd);

    fd = v6sock();
    memset(&a6, 0, sizeof(a6));
    a6.sin6_family = AF_INET;
    errno = 0; t("v6sock_famv4", bind(fd, (struct sockaddr *)&a6, sizeof(a6)));
    close(fd);

    /* AF_UNSPEC on a v4 socket: accepted with INADDR_ANY, EAFNOSUPPORT with a
       non-zero address (Linux __inet_bind AF_UNSPEC exception). */
    fd = v4sock();
    memset(&a4, 0, sizeof(a4));
    a4.sin_family = AF_UNSPEC;
    a4.sin_addr.s_addr = htonl(INADDR_ANY);
    errno = 0; t("v4_unspec_any", bind(fd, (struct sockaddr *)&a4, sizeof(a4)));
    close(fd);

    fd = v4sock();
    memset(&a4, 0, sizeof(a4));
    a4.sin_family = AF_UNSPEC;
    a4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    errno = 0; t("v4_unspec_nonzero", bind(fd, (struct sockaddr *)&a4, sizeof(a4)));
    close(fd);

    /* AF_UNSPEC on a v6 socket: no exception, EAFNOSUPPORT. */
    fd = v6sock();
    memset(&a6, 0, sizeof(a6));
    a6.sin6_family = AF_UNSPEC;
    errno = 0; t("v6_unspec", bind(fd, (struct sockaddr *)&a6, sizeof(a6)));
    close(fd);

    /* A normal loopback bind of each family succeeds. */
    fd = v4sock();
    memset(&a4, 0, sizeof(a4));
    a4.sin_family = AF_INET;
    a4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    errno = 0; t("v4_ok", bind(fd, (struct sockaddr *)&a4, sizeof(a4)));
    close(fd);

    fd = v6sock();
    memset(&a6, 0, sizeof(a6));
    a6.sin6_family = AF_INET6;
    a6.sin6_addr = in6addr_loopback;
    errno = 0; t("v6_ok", bind(fd, (struct sockaddr *)&a6, sizeof(a6)));
    close(fd);

    /* Bad fd. */
    errno = 0; t("badfd", bind(-1, (struct sockaddr *)&a4, sizeof(a4)));
    return 0;
}
