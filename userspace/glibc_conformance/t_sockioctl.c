/* Linux socket queue-ioctl corpus; output is compared verbatim by N24. */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static const char queued[] = "corked";
enum { TCP_CORK_ENABLED = 1 };

static void print_ioctl(const char *name, int fd) {
    int value = 0;
    errno = 0;
    int rc = ioctl(fd, SIOCOUTQNSD, &value);
    printf("%s rc=%d errno=%d value=%d\n", name, rc, errno, value);
}

static void owner_aliases(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int owner = 0;
    int got = 0;
    if (fd < 0) { puts("owner=socket_failed"); return; }
    errno = 0;
    int set_rc = ioctl(fd, FIOSETOWN, &owner);
    int set_errno = errno;
    errno = 0;
    int get_rc = ioctl(fd, FIOGETOWN, &got);
    int get_errno = errno;
    printf("owner fio set=%d errno=%d get=%d errno=%d value=%d\n", set_rc,
        set_errno, get_rc, get_errno, got);
    got = -1;
    errno = 0;
    set_rc = ioctl(fd, SIOCSPGRP, &owner);
    set_errno = errno;
    errno = 0;
    get_rc = ioctl(fd, SIOCGPGRP, &got);
    get_errno = errno;
    printf("owner sioc set=%d errno=%d get=%d errno=%d value=%d\n", set_rc,
        set_errno, get_rc, get_errno, got);
    close(fd);
}

int main(void) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int listener;
    int client;
    int accepted;
    int udp;
    int cork = TCP_CORK_ENABLED;

    client = socket(AF_INET, SOCK_STREAM, 0);
    udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (client < 0 || udp < 0) { puts("setup=socket_failed"); return 0; }
    print_ioctl("tcp_init", client);
    print_ioctl("udp", udp);
    owner_aliases();

    listener = socket(AF_INET, SOCK_STREAM, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (listener < 0 || bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0
        || listen(listener, SOMAXCONN) != 0
        || getsockname(listener, (struct sockaddr *)&addr, &addr_len) != 0) {
        puts("setup=listener_failed"); return 0;
    }
    print_ioctl("tcp_listener", listener);

    if (connect(client, (struct sockaddr *)&addr, addr_len) != 0) {
        puts("setup=connect_failed"); return 0;
    }
    accepted = accept(listener, NULL, NULL);
    if (accepted < 0 || setsockopt(client, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork)) != 0
        || write(client, queued, sizeof(queued) - sizeof(queued[0])) < 0) {
        puts("setup=queue_failed"); return 0;
    }
    print_ioctl("tcp_corked", client);
    close(accepted);
    close(listener);
    close(client);
    close(udp);
    return 0;
}
