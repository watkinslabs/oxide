/* Linux row-48 shutdown(2) corpus; output is compared verbatim by N12. */
#define _GNU_SOURCE
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void sd(const char *label, int fd, int how) {
    errno = 0;
    int rc = shutdown(fd, how);
    printf("%s rc=%d errno=%d\n", label, rc < 0 ? -1 : 0, rc < 0 ? errno : 0);
}

static int bound_listener(struct sockaddr_in *addr) {
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

/* On a connected TCP pair, SHUT_WR on one end must deliver EOF (read()==0) to
   the peer; that is the observable Linux contract for the send direction. */
static void connected_eof(void) {
    struct sockaddr_in addr;
    int listener = bound_listener(&addr);
    int client, server;
    char buf[4];
    if (listener < 0) { puts("eof=setup_failed"); return; }
    client = socket(AF_INET, SOCK_STREAM, 0);
    if (client < 0 || connect(client, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        puts("eof=connect_failed"); close(listener);
        if (client >= 0) close(client); return;
    }
    server = accept(listener, NULL, NULL);
    if (server < 0) { puts("eof=accept_failed"); close(listener); close(client); return; }

    sd("connected_shut_wr", client, SHUT_WR);
    ssize_t n = read(server, buf, sizeof(buf));
    printf("peer_reads_eof=%d\n", n == 0);
    /* A second SHUT_WR on an already write-closed socket still succeeds. */
    sd("double_shut_wr", client, SHUT_WR);
    /* SHUT_RDWR on the still-open server end succeeds. */
    sd("server_shut_rdwr", server, SHUT_RDWR);
    close(server); close(client); close(listener);
}

int main(void) {
    int bad = socket(AF_INET, SOCK_STREAM, 0);
    /* Invalid `how` outranks the unconnected state: Linux validates how first. */
    sd("badhow_unconn", bad, 3);
    sd("badhow_neg", bad, -1);
    /* Unconnected stream socket: ENOTCONN. */
    sd("tcp_unconn_rd", bad, SHUT_RD);
    sd("tcp_unconn_wr", bad, SHUT_WR);
    close(bad);

    /* Linux `udp`/`inet_shutdown` allows shutdown on an unconnected datagram
       socket (no ENOTCONN) — it just marks the shutdown state. */
    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    sd("udp_unconn_rd", udp, SHUT_RD);
    sd("udp_unconn_rdwr", udp, SHUT_RDWR);
    sd("udp_badhow", udp, 7);
    close(udp);

    /* A listening socket accepts SHUT_RDWR (it stops accepting). */
    struct sockaddr_in addr;
    int listener = bound_listener(&addr);
    if (listener >= 0) { sd("listener_rdwr", listener, SHUT_RDWR); close(listener); }

    /* Bad fd: EBADF, before any how validation. */
    sd("badfd", -1, SHUT_RD);
    sd("badfd_badhow", -1, 9);

    connected_eof();
    return 0;
}
