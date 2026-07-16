// /bin/msix_net_rx_probe - live virtio-net RX proof for MSI-X enable.
// Configures QEMU user-net eth0, sends a DNS query to slirp, and requires the
// inbound reply. The RX reply is delivered through virtio-net queue MSI-X.

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static const char *IFACE = "eth0";
static const char *LOCAL_IP = "10.0.2.15";
static const char *NETMASK = "255.255.255.0";
static const char *GATEWAY = "10.0.2.2";
static const char *DNS_IP = "10.0.2.3";
enum { DNS_PORT = 53, DNS_RETRIES = 300, DNS_WAIT_US = 10000 };
enum { AF_PACKET_LOCAL = 17, SOCK_RAW_LOCAL = 3, ETH_P_ALL = 0x0003 };
enum { ETH_ALEN_LOCAL = 6, ETH_HDR_LEN = 14, ETH_P_ARP = 0x0806 };
enum { ARP_HTYPE_ETH = 1, ARP_OP_REQUEST = 1, ARP_OP_REPLY = 2 };
enum { ARP_BODY_LEN = 28, ARP_FRAME_LEN = ETH_HDR_LEN + ARP_BODY_LEN };

struct sockaddr_ll_local {
    unsigned short sll_family;
    unsigned short sll_protocol;
    int sll_ifindex;
    unsigned short sll_hatype;
    unsigned char sll_pkttype;
    unsigned char sll_halen;
    unsigned char sll_addr[8];
};

static void bind_log_output(void) {
    int fd = open("/dev/ttyS0", O_WRONLY);
    if (fd < 0) fd = open("/dev/console", O_WRONLY);
    if (fd >= 0) {
        dup2(fd, 1);
        dup2(fd, 2);
        if (fd > 2) close(fd);
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

static void say(const char *msg) { write(1, msg, strlen(msg)); }

static unsigned short htons16(unsigned short v) {
    return ((v & 0xff) << 8) | ((v >> 8) & 0xff);
}

static long read_stat(const char *field) {
    char path[96];
    snprintf(path, sizeof(path), "/sys/class/net/eth0/statistics/%s", field);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    char buf[32];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    long v = 0;
    for (ssize_t i = 0; i < n; i++) {
        if (buf[i] < '0' || buf[i] > '9') break;
        v = v * 10 + (buf[i] - '0');
    }
    return v;
}

static void print_stats(const char *tag) {
    printf("msix_net_rx_probe: %s rx=%ld tx=%ld txerr=%ld\n",
        tag, read_stat("rx_packets"), read_stat("tx_packets"),
        read_stat("tx_errors"));
}

static void sockaddr_ipv4(struct sockaddr *sa, const char *ip, unsigned short port) {
    struct sockaddr_in *in = (struct sockaddr_in *)sa;
    memset(in, 0, sizeof(*in));
    in->sin_family = AF_INET;
    in->sin_port = htons(port);
    inet_pton(AF_INET, ip, &in->sin_addr);
}

static int set_addr_ioctl(int fd, unsigned long req, const char *ip, const char *tag) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, IFACE, IFNAMSIZ - 1);
    sockaddr_ipv4(&ifr.ifr_addr, ip, 0);
    if (ioctl(fd, req, &ifr) < 0) {
        printf("msix_net_rx_probe: FAIL %s errno=%d\n", tag, errno);
        return 1;
    }
    return 0;
}

static int bring_eth0_up(int fd) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, IFACE, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        printf("msix_net_rx_probe: FAIL SIOCGIFFLAGS errno=%d\n", errno);
        return 1;
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
        printf("msix_net_rx_probe: FAIL SIOCSIFFLAGS errno=%d\n", errno);
        return 1;
    }
    return 0;
}

static int add_default_route(int fd) {
    struct rtentry rt;
    memset(&rt, 0, sizeof(rt));
    sockaddr_ipv4(&rt.rt_dst, "0.0.0.0", 0);
    sockaddr_ipv4(&rt.rt_gateway, GATEWAY, 0);
    sockaddr_ipv4(&rt.rt_genmask, "0.0.0.0", 0);
    rt.rt_flags = RTF_UP | RTF_GATEWAY;
    rt.rt_dev = (char *)IFACE;
    if (ioctl(fd, SIOCADDRT, &rt) < 0 && errno != EEXIST) {
        printf("msix_net_rx_probe: FAIL SIOCADDRT errno=%d\n", errno);
        return 1;
    }
    return 0;
}

static int eth0_ifindex(int fd) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, IFACE, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        printf("msix_net_rx_probe: FAIL SIOCGIFINDEX errno=%d\n", errno);
        return -1;
    }
    return ifr.ifr_ifindex;
}

static int eth0_mac(int fd, unsigned char mac[ETH_ALEN_LOCAL]) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, IFACE, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        printf("msix_net_rx_probe: FAIL SIOCGIFHWADDR errno=%d\n", errno);
        return 1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN_LOCAL);
    return 0;
}

static int check_interface_getters(int fd) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, IFACE, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFMTU, &ifr) < 0 || ifr.ifr_mtu <= 0) {
        printf("msix_net_rx_probe: FAIL SIOCGIFMTU errno=%d\n", errno);
        return 1;
    }
    printf("msix_net_rx_probe: ioctl mtu=%d\n", ifr.ifr_mtu);

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, IFACE, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFTXQLEN, &ifr) < 0 || ifr.ifr_qlen < 0) {
        printf("msix_net_rx_probe: FAIL SIOCGIFTXQLEN errno=%d\n", errno);
        return 1;
    }
    printf("msix_net_rx_probe: ioctl txqlen=%d\n", ifr.ifr_qlen);

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, IFACE, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0 || ifr.ifr_addr.sa_family != AF_INET) {
        printf("msix_net_rx_probe: FAIL SIOCGIFADDR errno=%d\n", errno);
        return 1;
    }
    printf("msix_net_rx_probe: ioctl addr family=%d\n", ifr.ifr_addr.sa_family);

    if (ioctl(fd, SIOCGIFNETMASK, &ifr) < 0 || ifr.ifr_netmask.sa_family != AF_INET) {
        printf("msix_net_rx_probe: FAIL SIOCGIFNETMASK errno=%d\n", errno);
        return 1;
    }
    if (ioctl(fd, SIOCGIFBRDADDR, &ifr) < 0 || ifr.ifr_broadaddr.sa_family != AF_INET) {
        printf("msix_net_rx_probe: FAIL SIOCGIFBRDADDR errno=%d\n", errno);
        return 1;
    }
    printf("msix_net_rx_probe: ioctl netmask+broadcast family=%d\n",
        ifr.ifr_broadaddr.sa_family);

    char records[sizeof(struct ifreq) * 16];
    struct ifconf conf = {
        .ifc_len = (int)sizeof(records),
        .ifc_buf = records,
    };
    if (ioctl(fd, SIOCGIFCONF, &conf) < 0 || conf.ifc_len < (int)sizeof(struct ifreq)) {
        printf("msix_net_rx_probe: FAIL SIOCGIFCONF errno=%d\n", errno);
        return 1;
    }
    printf("msix_net_rx_probe: ioctl ifconf_bytes=%d records=%d\n",
        conf.ifc_len, conf.ifc_len / (int)sizeof(struct ifreq));
    return 0;
}

static int configure_eth0(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { printf("msix_net_rx_probe: FAIL cfg socket errno=%d\n", errno); return 1; }
    int fail = bring_eth0_up(fd)
        || set_addr_ioctl(fd, SIOCSIFADDR, LOCAL_IP, "SIOCSIFADDR")
        || set_addr_ioctl(fd, SIOCSIFNETMASK, NETMASK, "SIOCSIFNETMASK")
        || add_default_route(fd);
    if (!fail) fail = check_interface_getters(fd);
    close(fd);
    return fail;
}

static void put_be16(unsigned char *p, unsigned short v) {
    p[0] = (unsigned char)(v >> 8);
    p[1] = (unsigned char)(v & 0xff);
}

static void put_ipv4(unsigned char *p, const char *ip) {
    struct in_addr addr;
    inet_pton(AF_INET, ip, &addr);
    memcpy(p, &addr.s_addr, sizeof(addr.s_addr));
}

static int arp_reply_seen(const unsigned char *frame, ssize_t len,
    const unsigned char mac[ETH_ALEN_LOCAL])
{
    if (len < ARP_FRAME_LEN) return 0;
    if (frame[12] != (ETH_P_ARP >> 8) || frame[13] != (ETH_P_ARP & 0xff)) return 0;
    const unsigned char *arp = frame + ETH_HDR_LEN;
    if (arp[6] != 0 || arp[7] != ARP_OP_REPLY) return 0;
    if (memcmp(frame, mac, ETH_ALEN_LOCAL) != 0) return 0;
    return 1;
}

static int packet_tx_probe(void) {
    int ctl = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctl < 0) { printf("msix_net_rx_probe: FAIL pkt ctl socket errno=%d\n", errno); return 1; }
    int ifindex = eth0_ifindex(ctl);
    unsigned char mac[ETH_ALEN_LOCAL] = {0};
    int mac_fail = eth0_mac(ctl, mac);
    close(ctl);
    if (ifindex < 0) return 1;
    if (mac_fail) return 1;

    int fd = socket(AF_PACKET_LOCAL, SOCK_RAW_LOCAL, htons16(ETH_P_ALL));
    if (fd < 0) { printf("msix_net_rx_probe: FAIL packet socket errno=%d\n", errno); return 1; }
    struct sockaddr_ll_local sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET_LOCAL;
    sll.sll_protocol = htons16(ETH_P_ALL);
    sll.sll_ifindex = ifindex;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        printf("msix_net_rx_probe: FAIL packet bind errno=%d\n", errno);
        close(fd);
        return 1;
    }
    unsigned char frame[ARP_FRAME_LEN] = {0};
    memset(frame, 0xff, ETH_ALEN_LOCAL);
    memcpy(frame + ETH_ALEN_LOCAL, mac, ETH_ALEN_LOCAL);
    put_be16(frame + 12, ETH_P_ARP);
    unsigned char *arp = frame + ETH_HDR_LEN;
    put_be16(arp, ARP_HTYPE_ETH);
    put_be16(arp + 2, 0x0800);
    arp[4] = ETH_ALEN_LOCAL;
    arp[5] = 4;
    put_be16(arp + 6, ARP_OP_REQUEST);
    memcpy(arp + 8, mac, ETH_ALEN_LOCAL);
    put_ipv4(arp + 14, LOCAL_IP);
    put_ipv4(arp + 24, GATEWAY);
    if (sendto(fd, frame, sizeof(frame), 0, (struct sockaddr *)&sll, sizeof(sll))
        != (ssize_t)sizeof(frame)) {
        printf("msix_net_rx_probe: FAIL packet sendto errno=%d\n", errno);
        close(fd);
        return 1;
    }
    unsigned char reply[1600];
    for (int i = 0; i < DNS_RETRIES; i++) {
        ssize_t n = recvfrom(fd, reply, sizeof(reply), MSG_DONTWAIT, NULL, NULL);
        if (arp_reply_seen(reply, n, mac)) {
            printf("msix_net_rx_probe: arp_reply bytes=%d\n", (int)n);
            close(fd);
            return 0;
        }
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            printf("msix_net_rx_probe: FAIL packet recvfrom errno=%d\n", errno);
            close(fd);
            return 1;
        }
        usleep(DNS_WAIT_US);
    }
    printf("msix_net_rx_probe: FAIL arp reply timeout\n");
    close(fd);
    return 1;
}

static int bind_socket_to_eth0(int fd) {
    char ifname[IFNAMSIZ];
    memset(ifname, 0, sizeof(ifname));
    strncpy(ifname, IFACE, IFNAMSIZ - 1);
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, sizeof(ifname)) < 0) {
        printf("msix_net_rx_probe: FAIL SO_BINDTODEVICE errno=%d\n", errno);
        return 1;
    }
    return 0;
}

static int dns_round_trip(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { printf("msix_net_rx_probe: FAIL dns socket errno=%d\n", errno); return 1; }
    if (bind_socket_to_eth0(fd)) { close(fd); return 1; }
    unsigned char query[] = {
        0x42,0x42, 0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
        5,'o','x','i','d','e', 4,'t','e','s','t', 0, 0x00,0x01, 0x00,0x01,
    };
    struct sockaddr dst;
    sockaddr_ipv4(&dst, DNS_IP, DNS_PORT);
    print_stats("before");
    if (sendto(fd, query, sizeof(query), 0, &dst, sizeof(struct sockaddr_in))
        != (ssize_t)sizeof(query)) {
        printf("msix_net_rx_probe: FAIL sendto errno=%d\n", errno);
        close(fd);
        return 1;
    }
    print_stats("after_send");
    unsigned char reply[512];
    struct sockaddr src;
    socklen_t slen = sizeof(src);
    for (int i = 0; i < DNS_RETRIES; i++) {
        ssize_t n = recvfrom(fd, reply, sizeof(reply), MSG_DONTWAIT, &src, &slen);
        if (n >= 12) {
            printf("msix_net_rx_probe: PASS rx=%d bytes from %s\n", (int)n, DNS_IP);
            close(fd);
            return 0;
        }
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            printf("msix_net_rx_probe: FAIL recvfrom errno=%d\n", errno);
            close(fd);
            return 1;
        }
        usleep(DNS_WAIT_US);
    }
    print_stats("after_timeout");
    say("msix_net_rx_probe: FAIL recvfrom timeout\n");
    close(fd);
    return 1;
}

int main(void) {
    bind_log_output();
    say("msix_net_rx_probe: START\n");
    if (configure_eth0()) return 1;
    print_stats("before_packet");
    if (packet_tx_probe()) return 1;
    print_stats("after_packet");
    return dns_round_trip();
}
