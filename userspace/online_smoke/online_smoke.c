// /bin/online_smoke — verify outbound network end-to-end after DHCP.
// Sends a tiny DNS query (A record for "oxide.test") to slirp's DNS
// proxy at 10.0.2.3:53, waits up to 2s for a response, prints PASS
// on any reply (NXDOMAIN counts — the round-trip is what matters).
// Exercises: UDP send via NetDev::xmit, route table lookup (F148),
// ARP resolve to gateway MAC (F149), inbound IPv4 deliver_rx, UDP
// recv queue, sys_recvfrom timeout.

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

#define PASS "online_smoke: PASS\n"
#define FAIL_SOCKET "online_smoke: socket FAIL\n"
#define FAIL_SEND   "online_smoke: sendto FAIL\n"
#define FAIL_RECV   "online_smoke: recvfrom timeout\n"

static unsigned short htons16(unsigned short v) {
    return ((v & 0xff) << 8) | ((v >> 8) & 0xff);
}

int main(int argc, char** argv, char** envp) {
    (void)argc; (void)argv; (void)envp;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { write(1, FAIL_SOCKET, sizeof(FAIL_SOCKET)-1); return 1; }

    // Minimal DNS query: id=0x4242, flags=RD, qdcount=1, question
    // "oxide.test" A IN.
    unsigned char q[] = {
        0x42,0x42, 0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
        5,'o','x','i','d','e', 4,'t','e','s','t', 0,
        0x00,0x01, 0x00,0x01,
    };

    struct sa_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port   = htons16(53);
    // 10.0.2.3 in network byte order (host LE → BE bytes 10,0,2,3).
    dst.sin_addr = (10u) | (0u << 8) | (2u << 16) | (3u << 24);

    if (sendto(fd, q, sizeof(q), 0, (struct sockaddr*)&dst, sizeof(dst))
        != (ssize_t)sizeof(q))
    {
        write(1, FAIL_SEND, sizeof(FAIL_SEND)-1); return 1;
    }

    // Poll recvfrom with MSG_DONTWAIT until ~2s elapse.
    #ifndef MSG_DONTWAIT
    #define MSG_DONTWAIT 0x40
    #endif
    unsigned char buf[512];
    struct sa_in src; memset(&src, 0, sizeof(src));
    unsigned int slen = sizeof(src);
    for (int i = 0; i < 200; i++) {
        ssize_t n = recvfrom(fd, buf, sizeof(buf), MSG_DONTWAIT,
                             (struct sockaddr*)&src, &slen);
        if (n >= 12) {
            // Got *something* with a DNS-shaped header. Print and return.
            char out[128];
            int len = snprintf(out, sizeof(out),
                "online_smoke: PASS rx=%d bytes from 10.0.2.3:53\n", (int)n);
            write(1, out, len);
            return 0;
        }
        if (n < 0 && errno != 11 /* EAGAIN */) {
            char out[64];
            int len = snprintf(out, sizeof(out),
                "online_smoke: recvfrom errno=%d\n", errno);
            write(1, out, len);
            return 1;
        }
        usleep(10000);
    }
    write(1, FAIL_RECV, sizeof(FAIL_RECV)-1);
    return 1;
}
