/* Linux row-42 connect(2) corpus; output is compared verbatim by N. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void step(const char *label, int rc) {
    printf("%s rc=%d errno=%d\n", label, rc < 0 ? -1 : 0, rc < 0 ? errno : 0);
}

static int connect_v4(int fd, unsigned port) {
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    errno = 0;
    return connect(fd, (struct sockaddr *)&a, sizeof(a));
}

/* A UDP connect just sets the default peer; a second connect re-points it, and
   AF_UNSPEC dissolves the association (Linux `udp_disconnect`). */
static void udp_default_peer(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { puts("udp=socket_failed"); return; }
    errno = 0; step("udp_connect1", connect_v4(fd, 40001));
    errno = 0; step("udp_reconnect", connect_v4(fd, 40002));
    struct sockaddr_in unspec;
    memset(&unspec, 0, sizeof(unspec));
    unspec.sin_family = AF_UNSPEC;
    errno = 0;
    step("udp_disconnect", connect(fd, (struct sockaddr *)&unspec, sizeof(unspec)));
    close(fd);
}

/* Short and mis-family sockaddrs. */
static void bad_addr(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { puts("bad=socket_failed"); return; }
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(40010);
    errno = 0;
    step("short_addrlen", connect(fd, (struct sockaddr *)&a, 4));
    /* Wrong family for an AF_INET socket. */
    struct sockaddr_in6 a6;
    memset(&a6, 0, sizeof(a6));
    a6.sin6_family = AF_INET6;
    errno = 0;
    step("wrong_family", connect(fd, (struct sockaddr *)&a6, sizeof(a6)));
    close(fd);
}

/* A connected TCP pair: a second connect is EISCONN; connecting the accepted
   server end is also EISCONN. */
static void connected_pair(void) {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    socklen_t alen = sizeof(a);
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (listener < 0 || bind(listener, (struct sockaddr *)&a, sizeof(a)) != 0
        || listen(listener, 4) != 0
        || getsockname(listener, (struct sockaddr *)&a, &alen) != 0) {
        puts("pair=setup_failed"); if (listener >= 0) close(listener); return;
    }
    int client = socket(AF_INET, SOCK_STREAM, 0);
    errno = 0;
    step("pair_connect", connect(client, (struct sockaddr *)&a, alen));
    int server = accept(listener, NULL, NULL);
    errno = 0;
    step("client_reconnect_eisconn", connect(client, (struct sockaddr *)&a, alen));
    if (server >= 0) {
        errno = 0;
        step("server_connect_eisconn", connect(server, (struct sockaddr *)&a, alen));
        close(server);
    }
    close(client); close(listener);
}

int main(void) {
    /* Bad fd before any address handling. */
    errno = 0; step("badfd", connect_v4(-1, 40000));

    /* Not a socket. */
    int pfd[2];
    if (pipe(pfd) == 0) {
        errno = 0; step("pipe_connect", connect_v4(pfd[0], 40000));
        close(pfd[0]); close(pfd[1]);
    }

    /* TCP connect to a port with no listener on loopback: ECONNREFUSED. */
    int t = socket(AF_INET, SOCK_STREAM, 0);
    errno = 0; step("tcp_refused", connect_v4(t, 1));
    close(t);

    bad_addr();
    udp_default_peer();
    connected_pair();
    return 0;
}
