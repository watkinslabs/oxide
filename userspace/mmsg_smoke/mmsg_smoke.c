// /bin/mmsg_smoke — sendmmsg/recvmmsg batch UDP loopback (phase 15).
// Server UDP socket bound to 127.0.0.1:port. Client sends 3 datagrams
// in ONE sendmmsg() call; server reads them in ONE recvmmsg() call.
// Verifies the mmsghdr vector ABI (msg_hdr + msg_len) and that each
// datagram arrives intact with the right per-message length.

#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef SOCK_DGRAM
#define SOCK_DGRAM 2
#endif

struct sa_in {
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned int   sin_addr;
    unsigned char  zero[8];
};
static unsigned short htons16(unsigned short v) {
    return ((v & 0xff) << 8) | ((v >> 8) & 0xff);
}
static unsigned int ip4(unsigned a, unsigned b, unsigned c, unsigned d) {
    return a | (b << 8) | (c << 16) | (d << 24);
}

#define PASS "mmsg_smoke: PASS\n"
static int fail(const char *why) {
    char b[96]; int n = snprintf(b, sizeof b, "mmsg_smoke: FAIL %s errno=%d\n", why, errno);
    write(1, b, n);
    return 1;
}

#define N 3

int main(void) {
    const unsigned short port = 9107;

    int srv = socket(AF_INET, SOCK_DGRAM, 0);
    if (srv < 0) return fail("srv-socket");
    struct sa_in la;
    memset(&la, 0, sizeof la);
    la.sin_family = AF_INET;
    la.sin_port   = htons16(port);
    la.sin_addr   = ip4(127,0,0,1);
    if (bind(srv, (struct sockaddr*)&la, sizeof la) < 0) return fail("bind");

    int cli = socket(AF_INET, SOCK_DGRAM, 0);
    if (cli < 0) return fail("cli-socket");

    const char *msgs[N] = { "alpha", "bravo", "charlie" };
    struct iovec iov[N];
    struct mmsghdr out[N];
    memset(out, 0, sizeof out);
    for (int i = 0; i < N; i++) {
        iov[i].iov_base = (void*)msgs[i];
        iov[i].iov_len  = strlen(msgs[i]);
        out[i].msg_hdr.msg_name    = &la;
        out[i].msg_hdr.msg_namelen = sizeof la;
        out[i].msg_hdr.msg_iov     = &iov[i];
        out[i].msg_hdr.msg_iovlen  = 1;
    }
    int sent = sendmmsg(cli, out, N, 0);
    if (sent != N) return fail("sendmmsg-count");

    // Receive all N in one call.
    char bufs[N][32];
    struct iovec riov[N];
    struct mmsghdr in[N];
    memset(in, 0, sizeof in);
    for (int i = 0; i < N; i++) {
        riov[i].iov_base = bufs[i];
        riov[i].iov_len  = sizeof bufs[i];
        in[i].msg_hdr.msg_iov    = &riov[i];
        in[i].msg_hdr.msg_iovlen = 1;
    }
    int got = recvmmsg(srv, in, N, 0, NULL);
    if (got != N) return fail("recvmmsg-count");

    // Datagram order is preserved on loopback; verify each.
    for (int i = 0; i < N; i++) {
        unsigned int want = strlen(msgs[i]);
        if (in[i].msg_len != want) return fail("msg_len");
        if (memcmp(bufs[i], msgs[i], want) != 0) return fail("payload");
    }

    write(1, PASS, sizeof(PASS) - 1);
    return 0;
}
