#include "probe.h"

#include <linux/netlink.h>

static int saved_errno(ssize_t rc) {
    return rc < 0 ? errno : 0;
}

static int unix_pair(int type, int pair[2]) {
    return socketpair(AF_UNIX, type | SOCK_NONBLOCK, 0, pair);
}

static int udp_loopback(struct sockaddr_in *addr) {
    socklen_t len = sizeof(*addr);
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fd < 0) return -1;
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)addr, sizeof(*addr)) < 0 ||
        getsockname(fd, (struct sockaddr *)addr, &len) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

static void ordering_and_faults(void) {
    char buf[16];
    int pair[2];
    size_t page_len = 0;
    void *fault = fault_page(&page_len);
    ssize_t badfd;
    ssize_t empty;
    ssize_t unix_fault;
    ssize_t unix_after;
    int badfd_errno;
    int empty_errno;
    int unix_fault_errno;
    int unix_after_errno;

    errno = 0;
    badfd = recvfrom(-1, (void *)(uintptr_t)-1, 0, MSG_DONTWAIT, NULL, NULL);
    badfd_errno = saved_errno(badfd);
    if (unix_pair(SOCK_DGRAM, pair) < 0) return;
    errno = 0;
    empty = recvfrom(pair[0], (void *)(uintptr_t)-1, 0, 0, NULL, NULL);
    empty_errno = saved_errno(empty);
    send(pair[1], "unix", 4, 0);
    errno = 0;
    unix_fault = recvfrom(pair[0], fault, 4, 0, NULL, NULL);
    unix_fault_errno = saved_errno(unix_fault);
    errno = 0;
    unix_after = recvfrom(pair[0], buf, sizeof(buf), 0, NULL, NULL);
    unix_after_errno = saved_errno(unix_after);
    out("recvfrom", "ordering_faults",
        "badfd=%zd:%s(%d)|empty_badbuf=%zd:%s(%d)|unix_fault=%zd:%s(%d)|unix_after=%zd:%s(%d)",
        badfd, errno_name(badfd_errno), badfd_errno,
        empty, errno_name(empty_errno), empty_errno,
        unix_fault, errno_name(unix_fault_errno), unix_fault_errno,
        unix_after, errno_name(unix_after_errno), unix_after_errno);
    close(pair[0]);
    close(pair[1]);
    if (fault != MAP_FAILED) munmap(fault, page_len);
}

static void udp_fault_consumes(void) {
    struct sockaddr_in addr;
    char buf[16];
    size_t page_len = 0;
    void *fault = fault_page(&page_len);
    int fd = udp_loopback(&addr);
    if (fd < 0) return;
    sendto(fd, "udp", 3, 0, (struct sockaddr *)&addr, sizeof(addr));
    errno = 0;
    ssize_t first = recvfrom(fd, fault, 3, 0, NULL, NULL);
    int first_errno = saved_errno(first);
    errno = 0;
    ssize_t after = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
    int after_errno = saved_errno(after);
    out("recvfrom", "udp_fault_consumes",
        "fault=%zd:%s(%d)|after=%zd:%s(%d)",
        first, errno_name(first_errno), first_errno,
        after, errno_name(after_errno), after_errno);
    close(fd);
    if (fault != MAP_FAILED) munmap(fault, page_len);
}

static void source_length_ordering(void) {
    struct sockaddr_storage source;
    char buf[16];
    int pair[2];
    socklen_t negative = (socklen_t)-1;
    ssize_t null_len;
    ssize_t null_after;
    ssize_t negative_len;
    ssize_t negative_after;
    ssize_t null_name;
    int e1, e2, e3, e4, e5;

    if (unix_pair(SOCK_DGRAM, pair) < 0) return;
    send(pair[1], "one", 3, 0);
    errno = 0;
    null_len = recvfrom(pair[0], buf, sizeof(buf), 0,
        (struct sockaddr *)&source, NULL);
    e1 = saved_errno(null_len);
    errno = 0;
    null_after = recvfrom(pair[0], buf, sizeof(buf), 0, NULL, NULL);
    e2 = saved_errno(null_after);
    send(pair[1], "two", 3, 0);
    errno = 0;
    negative_len = recvfrom(pair[0], buf, sizeof(buf), 0,
        (struct sockaddr *)&source, &negative);
    e3 = saved_errno(negative_len);
    errno = 0;
    negative_after = recvfrom(pair[0], buf, sizeof(buf), 0, NULL, NULL);
    e4 = saved_errno(negative_after);
    send(pair[1], "tri", 3, 0);
    errno = 0;
    null_name = recvfrom(pair[0], buf, sizeof(buf), 0, NULL,
        (socklen_t *)(uintptr_t)-1);
    e5 = saved_errno(null_name);
    out("recvfrom", "source_length",
        "null=%zd:%s(%d)|null_after=%zd:%s(%d)|negative=%zd:%s(%d)|negative_after=%zd:%s(%d)|null_name=%zd:%s(%d)",
        null_len, errno_name(e1), e1, null_after, errno_name(e2), e2,
        negative_len, errno_name(e3), e3,
        negative_after, errno_name(e4), e4,
        null_name, errno_name(e5), e5);
    close(pair[0]);
    close(pair[1]);
}

static void flag_semantics(void) {
    struct sockaddr_in addr;
    char buf[16];
    int stream[2];
    int dgram[2];
    int udp;
    ssize_t stream_oob, stream_after, dgram_oob, dgram_after;
    ssize_t udp_oob, udp_after, errqueue, errqueue_after;
    int e1, e2, e3, e4, e5, e6, e7, e8;

    if (unix_pair(SOCK_STREAM, stream) < 0 || unix_pair(SOCK_DGRAM, dgram) < 0)
        return;
    udp = udp_loopback(&addr);
    if (udp < 0) return;
    send(stream[1], "s", 1, 0);
    errno = 0; stream_oob = recvfrom(stream[0], buf, sizeof(buf), MSG_OOB, NULL, NULL); e1 = saved_errno(stream_oob);
    errno = 0; stream_after = recvfrom(stream[0], buf, sizeof(buf), 0, NULL, NULL); e2 = saved_errno(stream_after);
    send(dgram[1], "d", 1, 0);
    errno = 0; dgram_oob = recvfrom(dgram[0], buf, sizeof(buf), MSG_OOB, NULL, NULL); e3 = saved_errno(dgram_oob);
    errno = 0; dgram_after = recvfrom(dgram[0], buf, sizeof(buf), 0, NULL, NULL); e4 = saved_errno(dgram_after);
    sendto(udp, "u", 1, 0, (struct sockaddr *)&addr, sizeof(addr));
    errno = 0; udp_oob = recvfrom(udp, buf, sizeof(buf), MSG_OOB, NULL, NULL); e5 = saved_errno(udp_oob);
    errno = 0; udp_after = recvfrom(udp, buf, sizeof(buf), 0, NULL, NULL); e6 = saved_errno(udp_after);
    send(dgram[1], "e", 1, 0);
    errno = 0; errqueue = recvfrom(dgram[0], buf, sizeof(buf), MSG_ERRQUEUE, NULL, NULL); e7 = saved_errno(errqueue);
    errno = 0; errqueue_after = recvfrom(dgram[0], buf, sizeof(buf), 0, NULL, NULL); e8 = saved_errno(errqueue_after);
    out("recvfrom", "flags",
        "stream_oob=%zd:%s(%d)|stream_after=%zd:%s(%d)|dgram_oob=%zd:%s(%d)|dgram_after=%zd:%s(%d)|udp_oob=%zd:%s(%d)|udp_after=%zd:%s(%d)|errqueue=%zd:%s(%d)|errqueue_after=%zd:%s(%d)",
        stream_oob, errno_name(e1), e1, stream_after, errno_name(e2), e2,
        dgram_oob, errno_name(e3), e3, dgram_after, errno_name(e4), e4,
        udp_oob, errno_name(e5), e5, udp_after, errno_name(e6), e6,
        errqueue, errno_name(e7), e7, errqueue_after, errno_name(e8), e8);
    close(stream[0]); close(stream[1]); close(dgram[0]); close(dgram[1]); close(udp);
}

static int tcp_pair(int *client, int *server) {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    if (listener < 0) return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(listener, 1) < 0 || getsockname(listener, (struct sockaddr *)&addr, &len) < 0) {
        close(listener); return -1;
    }
    *client = socket(AF_INET, SOCK_STREAM, 0);
    if (*client < 0 || connect(*client, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(listener); if (*client >= 0) close(*client); return -1;
    }
    *server = accept(listener, NULL, NULL);
    close(listener);
    return *server < 0 ? -1 : 0;
}

static void tcp_oob_semantics(void) {
    int client = -1, server = -1;
    char buf[8] = {0};
    int atmark = -1;
    ssize_t ordinary, oob, after;
    int e1, e2, e3;
    if (tcp_pair(&client, &server) < 0) return;
    send(client, "a", 1, 0);
    send(client, "!", 1, MSG_OOB);
    errno = 0; ordinary = recv(server, buf, sizeof(buf), 0); e1 = saved_errno(ordinary);
    errno = 0; ioctl(server, SIOCATMARK, &atmark); e2 = errno;
    errno = 0; oob = recv(server, buf, sizeof(buf), MSG_OOB); e3 = saved_errno(oob);
    errno = 0; after = recv(server, buf, sizeof(buf), MSG_DONTWAIT);
    out("recvfrom", "tcp_oob",
        "ordinary=%zd:%s(%d)|mark=%d:%s(%d)|oob=%zd:%s(%d)|after=%zd:%s(%d)",
        ordinary, errno_name(e1), e1, atmark, errno_name(e2), e2,
        oob, errno_name(e3), e3, after, errno_name(saved_errno(after)), saved_errno(after));
    close(client); close(server);

    if (tcp_pair(&client, &server) < 0) return;
    int inline_mode = 1;
    setsockopt(server, SOL_SOCKET, SO_OOBINLINE, &inline_mode, sizeof(inline_mode));
    send(client, "a", 1, 0); send(client, "!", 1, MSG_OOB);
    errno = 0; ssize_t inlined = recv(server, buf, sizeof(buf), MSG_DONTWAIT);
    errno = 0; ssize_t inline_tail = recv(server, buf + inlined, sizeof(buf) - (size_t)(inlined > 0 ? inlined : 0), MSG_DONTWAIT);
    out("recvfrom", "tcp_oob_inline", "recv=%zd:%s(%d)|tail=%zd:%s(%d)|bytes=%02x%02x",
        inlined, errno_name(saved_errno(inlined)), saved_errno(inlined),
        inline_tail, errno_name(saved_errno(inline_tail)), saved_errno(inline_tail),
        (unsigned char)buf[0], (unsigned char)buf[1]);
    close(client); close(server);
}

void probe_recvfrom(void) {
    ordering_and_faults();
    udp_fault_consumes();
    source_length_ordering();
    flag_semantics();
    tcp_oob_semantics();
}
