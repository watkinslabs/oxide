/* Linux rows 51/52 getsockname/getpeername corpus; verbatim-compared by N15. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static unsigned name_port(const struct sockaddr_storage *ss) {
    if (ss->ss_family == AF_INET)
        return ntohs(((const struct sockaddr_in *)ss)->sin_port);
    if (ss->ss_family == AF_INET6)
        return ntohs(((const struct sockaddr_in6 *)ss)->sin6_port);
    return 0;
}

/* Report a name query. The auto-assigned ephemeral port is non-deterministic,
   so print only whether a port was assigned; fixed ports are asserted by the
   fixed-port cases. Family and length are the deterministic ABI. */
static void show_name(const char *label, int rc, int err, socklen_t len,
    const struct sockaddr_storage *ss) {
    if (rc != 0) { printf("%s rc=%d errno=%d\n", label, rc, err); return; }
    printf("%s rc=0 family=%d len=%u port_set=%d\n", label, ss->ss_family,
        (unsigned)len, name_port(ss) != 0);
}

/* A case that binds a known port asserts the exact value. */
static void show_fixed_port(const char *label, int fd, unsigned expect) {
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    socklen_t len = sizeof(ss);
    errno = 0;
    int rc = getsockname(fd, (struct sockaddr *)&ss, &len);
    if (rc != 0) { printf("%s rc=%d errno=%d\n", label, rc, errno); return; }
    printf("%s rc=0 family=%d len=%u port_match=%d\n", label, ss.ss_family,
        (unsigned)len, name_port(&ss) == expect);
}

static void local(const char *label, int fd) {
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    socklen_t len = sizeof(ss);
    errno = 0;
    int rc = getsockname(fd, (struct sockaddr *)&ss, &len);
    show_name(label, rc, errno, len, &ss);
}

static void peer(const char *label, int fd) {
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    socklen_t len = sizeof(ss);
    errno = 0;
    int rc = getpeername(fd, (struct sockaddr *)&ss, &len);
    show_name(label, rc, errno, len, &ss);
}

/* Linux copies min(actual, supplied) bytes, then writes the ACTUAL length back
   through the value-result pointer even when the buffer was too small. */
static void truncated_local(const char *label, int fd, socklen_t supplied) {
    unsigned char buf[128];
    memset(buf, 0xcc, sizeof(buf));
    socklen_t len = supplied;
    errno = 0;
    int rc = getsockname(fd, (struct sockaddr *)buf, &len);
    printf("%s rc=%d errno=%d ret_len=%u byte_after=%u\n", label, rc, errno,
        (unsigned)len, supplied < sizeof(buf) ? buf[supplied] : 0);
}

static int bound_inet(int type, unsigned short port) {
    int fd = socket(AF_INET, type, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    if (fd < 0 || bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    return fd;
}

/* A connected TCP pair exercises getpeername on both ends. Linux guarantees
   client_local == server_peer and client_peer == server_local == listener. */
static unsigned addr_port(int fd, int (*query)(int, struct sockaddr *, socklen_t *)) {
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    socklen_t len = sizeof(ss);
    if (query(fd, (struct sockaddr *)&ss, &len) != 0) return 0;
    return name_port(&ss);
}

static void connected_pair(unsigned listen_port) {
    int listener = bound_inet(SOCK_STREAM, listen_port);
    struct sockaddr_in a;
    socklen_t alen = sizeof(a);
    int client, server;
    if (listener < 0 || listen(listener, 1) != 0
        || getsockname(listener, (struct sockaddr *)&a, &alen) != 0) {
        puts("pair=setup_failed"); if (listener >= 0) close(listener); return;
    }
    client = socket(AF_INET, SOCK_STREAM, 0);
    if (client < 0 || connect(client, (struct sockaddr *)&a, alen) != 0) {
        puts("pair=connect_failed"); close(listener);
        if (client >= 0) close(client); return;
    }
    server = accept(listener, NULL, NULL);
    if (server < 0) { puts("pair=accept_failed"); close(listener); close(client); return; }
    unsigned cl = addr_port(client, getsockname);
    unsigned cp = addr_port(client, getpeername);
    unsigned sl = addr_port(server, getsockname);
    unsigned sp = addr_port(server, getpeername);
    printf("pair local_matches_peer=%d peer_is_listener=%d server_local_is_listener=%d\n",
        cl == sp, cp == listen_port, sl == listen_port);
    close(server); close(client); close(listener);
}

int main(void) {
    int bad_fd_probe = -1;
    local("badfd_local", bad_fd_probe);
    peer("badfd_peer", bad_fd_probe);

    /* A pipe read end is a valid fd but not a socket. */
    int pfd[2];
    if (pipe(pfd) == 0) { local("pipe_local", pfd[0]); close(pfd[0]); close(pfd[1]); }

    int u = socket(AF_INET, SOCK_DGRAM, 0);
    local("udp_unbound_local", u);   /* family AF_INET, port 0 */
    peer("udp_unbound_peer", u);     /* ENOTCONN */
    close(u);

    int t = socket(AF_INET, SOCK_STREAM, 0);
    local("tcp_unbound_local", t);
    peer("tcp_unbound_peer", t);
    close(t);

    int b = bound_inet(SOCK_DGRAM, 39001);
    if (b >= 0) { show_fixed_port("udp_bound_local", b, 39001);
        truncated_local("udp_trunc4", b, 4);
        truncated_local("udp_trunc_zero", b, 0); close(b); }

    int s6 = socket(AF_INET6, SOCK_DGRAM, 0);
    struct sockaddr_in6 a6;
    memset(&a6, 0, sizeof(a6));
    a6.sin6_family = AF_INET6;
    a6.sin6_addr = in6addr_loopback;
    a6.sin6_port = htons(39002);
    if (s6 >= 0 && bind(s6, (struct sockaddr *)&a6, sizeof(a6)) == 0)
        show_fixed_port("udp6_bound_local", s6, 39002);
    if (s6 >= 0) close(s6);

    int un = socket(AF_UNIX, SOCK_STREAM, 0);
    local("unix_unbound_local", un);  /* Linux: family AF_UNIX, len 2 */
    peer("unix_unbound_peer", un);    /* ENOTCONN */
    if (un >= 0) close(un);

    connected_pair(39003);
    return 0;
}
