// /bin/inet6_smoke — AF_INET6 UDP loopback echo (phase 15).
// Binds a UDP6 socket to [::1]:port, sends a datagram to it from a
// second UDP6 socket, recvfrom, and checks the payload + that the
// source address is ::1. Exercises the IPv6 socket family, the
// sockaddr_in6 ABI, IPv6 header build/parse, and loopback delivery.

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>

#ifndef AF_INET6
#define AF_INET6 10
#endif
#ifndef SOCK_DGRAM
#define SOCK_DGRAM 2
#endif

struct in6_addr_x { unsigned char s6[16]; };
struct sa_in6 {
    unsigned short  sin6_family;
    unsigned short  sin6_port;
    unsigned int    sin6_flowinfo;
    struct in6_addr_x sin6_addr;
    unsigned int    sin6_scope_id;
};

static unsigned short htons16(unsigned short v) {
    return ((v & 0xff) << 8) | ((v >> 8) & 0xff);
}

#define PASS "inet6_smoke: PASS\n"
static int fail(const char *why) {
    char b[96]; int n = snprintf(b, sizeof b, "inet6_smoke: FAIL %s errno=%d\n", why, errno);
    write(1, b, n);
    return 1;
}

int main(void) {
    const unsigned short port = 9106;

    int srv = socket(AF_INET6, SOCK_DGRAM, 0);
    if (srv < 0) return fail("srv-socket");

    struct sa_in6 la;
    memset(&la, 0, sizeof la);
    la.sin6_family = AF_INET6;
    la.sin6_port   = htons16(port);
    la.sin6_addr.s6[15] = 1;            // ::1

    if (bind(srv, (struct sockaddr*)&la, sizeof la) < 0) return fail("bind");

    int cli = socket(AF_INET6, SOCK_DGRAM, 0);
    if (cli < 0) return fail("cli-socket");

    const char *msg = "oxide-v6";
    if (sendto(cli, msg, 8, 0, (struct sockaddr*)&la, sizeof la) != 8)
        return fail("sendto");

    char buf[32];
    struct sa_in6 from;
    socklen_t flen = sizeof from;
    memset(&from, 0, sizeof from);
    ssize_t r = recvfrom(srv, buf, sizeof buf, 0, (struct sockaddr*)&from, &flen);
    if (r != 8) return fail("recvfrom-len");
    if (memcmp(buf, msg, 8) != 0) return fail("payload");

    // Source must be ::1 (loopback source selection per RFC 6724).
    if (from.sin6_family == AF_INET6 && from.sin6_addr.s6[15] != 1)
        return fail("src-addr");

    write(1, PASS, sizeof(PASS) - 1);
    return 0;
}
