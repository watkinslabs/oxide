// /bin/af_packet_smoke — verifies AF_PACKET TX (F135). Uses
// inline sockaddr_ll + SIOCGIFINDEX layout to avoid pulling in
// linux/if_packet.h (we don't stage that header in the smoke
// build flags).

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#ifndef AF_PACKET
#define AF_PACKET     17
#endif
#ifndef SOCK_RAW
#define SOCK_RAW      3
#endif
#define ETH_P_ALL     0x0003
#define SIOCGIFINDEX  0x8933
#define IFNAMSIZ      16

struct sockaddr_ll {
    unsigned short sll_family;
    unsigned short sll_protocol;   // big-endian
    int            sll_ifindex;
    unsigned short sll_hatype;
    unsigned char  sll_pkttype;
    unsigned char  sll_halen;
    unsigned char  sll_addr[8];
};

struct ifreq_local {
    char  ifr_name[IFNAMSIZ];
    union {
        int ifr_ifindex;
        char pad[24];
    } u;
};

static unsigned short htons16(unsigned short v) {
    return ((v & 0xff) << 8) | ((v >> 8) & 0xff);
}

#define PASS "af_packet_smoke: PASS\n"
#define FAIL_SOCKET "af_packet_smoke: socket FAIL\n"
#define FAIL_IDX    "af_packet_smoke: SIOCGIFINDEX FAIL\n"
#define FAIL_BIND   "af_packet_smoke: bind FAIL\n"
#define FAIL_SEND   "af_packet_smoke: sendto FAIL\n"

int main(int argc, char** argv, char** envp) {
    (void)argc; (void)argv; (void)envp;
    int fd = socket(AF_PACKET, SOCK_RAW, htons16(ETH_P_ALL));
    if (fd < 0) { write(1, FAIL_SOCKET, sizeof(FAIL_SOCKET)-1); return 1; }

    struct ifreq_local ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        { char b[64]; int n = snprintf(b, sizeof(b), "af_packet_smoke: SIOCGIFINDEX errno=%d\n", errno); write(1, b, n); return 1; }
    }
    int idx = ifr.u.ifr_ifindex;

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons16(ETH_P_ALL);
    sll.sll_ifindex  = idx;
    if (bind(fd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        write(1, FAIL_BIND, sizeof(FAIL_BIND)-1); return 1;
    }

    unsigned char frame[60] = {0};
    memset(frame, 0xff, 6);                    // dst MAC = broadcast
    frame[12] = 0x88; frame[13] = 0xB5;        // ethertype experimental
    frame[14] = 'O'; frame[15] = 'X'; frame[16] = 'I';
    frame[17] = 'D'; frame[18] = 'E';
    if (sendto(fd, frame, sizeof(frame), 0,
               (struct sockaddr*)&sll, sizeof(sll)) != (ssize_t)sizeof(frame))
    {
        write(1, FAIL_SEND, sizeof(FAIL_SEND)-1); return 1;
    }

    // F140: exercise the RX path. With MSG_DONTWAIT and no frames
    // queued the kernel must return -1/EAGAIN (not EINVAL); on a
    // real rx (slirp ARP / DHCPOFFER replay), we'd see the L2
    // frame in `buf` and a populated sockaddr_ll in `peer`.
    #ifndef MSG_DONTWAIT
    #define MSG_DONTWAIT 0x40
    #endif
    unsigned char rxbuf[1500];
    struct sockaddr_ll peer; memset(&peer, 0, sizeof(peer));
    unsigned int plen = sizeof(peer);
    ssize_t r = recvfrom(fd, rxbuf, sizeof(rxbuf), MSG_DONTWAIT,
                        (struct sockaddr*)&peer, &plen);
    if (r < 0 && errno != 11 /* EAGAIN */) {
        char b[64]; int n = snprintf(b, sizeof(b), "af_packet_smoke: recvfrom errno=%d\n", errno);
        write(1, b, n); return 1;
    }
    if (r > 0 && peer.sll_family != AF_PACKET) {
        write(1, "af_packet_smoke: peer sll_family wrong\n", 39); return 1;
    }
    write(1, PASS, sizeof(PASS)-1);
    return 0;
}
