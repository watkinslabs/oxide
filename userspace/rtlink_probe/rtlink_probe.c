// /bin/rtlink_probe — RTM_GETLINK dump (K4). systemd-networkd + iproute2
// `ip link` enumerate interfaces with a NETLINK_ROUTE RTM_GETLINK dump:
// send one request with NLM_F_REQUEST|NLM_F_DUMP, then read the multipart
// stream of RTM_NEWLINK replies terminated by NLMSG_DONE. This reproduces
// that exact sequence and asserts: at least one interface is returned,
// each carries an IFLA_IFNAME, and the dump terminates with NLMSG_DONE
// (the "EOF on netlink" failure mode is no DONE / a truncated stream).

#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>

#ifndef AF_NETLINK
#define AF_NETLINK 16
#endif
#ifndef NETLINK_ROUTE
#define NETLINK_ROUTE 0
#endif
#define NLM_F_REQUEST 0x01
#define NLM_F_DUMP    0x0300
#define RTM_GETLINK   18
#define RTM_NEWLINK   16
#define NLMSG_DONE    3
#define IFLA_IFNAME   3

struct nlmsghdr_ { unsigned int len; unsigned short type, flags; unsigned int seq, pid; };
struct ifinfomsg_ { unsigned char family, pad; unsigned short type; int index; unsigned flags, change; };
#define NLA(p, off) ((unsigned short *)((char *)(p) + (off)))

int main(void) {
    int s = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (s < 0) { printf("rtlink_probe: FAIL socket errno=%d\n", errno); return 1; }

    // Build RTM_GETLINK dump request.
    struct { struct nlmsghdr_ nh; struct ifinfomsg_ ifi; } req;
    memset(&req, 0, sizeof req);
    req.nh.len   = sizeof req;
    req.nh.type  = RTM_GETLINK;
    req.nh.flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nh.seq   = 1;
    req.ifi.family = 0; // AF_UNSPEC
    if (send(s, &req, sizeof req, 0) < 0) {
        printf("rtlink_probe: FAIL send errno=%d\n", errno); return 1;
    }

    int links = 0, named = 0, done = 0;
    for (int iter = 0; iter < 64 && !done; iter++) {
        char buf[8192];
        int n = recv(s, buf, sizeof buf, 0);
        if (n <= 0) {
            // EAGAIN before DONE = the bug; anything else = hard fail.
            printf("rtlink_probe: FAIL recv n=%d errno=%d (links=%d done=%d)\n", n, errno, links, done);
            return 1;
        }
        int off = 0;
        while (off + (int)sizeof(struct nlmsghdr_) <= n) {
            struct nlmsghdr_ *nh = (struct nlmsghdr_ *)(buf + off);
            if (nh->len < sizeof(struct nlmsghdr_) || off + (int)nh->len > n) break;
            if (nh->type == NLMSG_DONE) { done = 1; break; }
            if (nh->type == RTM_NEWLINK) {
                links++;
                // Scan IFLA attrs for IFLA_IFNAME.
                int ao = sizeof(struct nlmsghdr_) + ((sizeof(struct ifinfomsg_) + 3) & ~3);
                while (ao + 4 <= (int)nh->len) {
                    unsigned short alen = *NLA(nh, ao);
                    unsigned short atyp = *NLA(nh, ao + 2);
                    if (alen < 4) break;
                    if (atyp == IFLA_IFNAME) named++;
                    ao += (alen + 3) & ~3;
                }
            }
            off += (nh->len + 3) & ~3;
        }
    }

    if (!done)  { printf("rtlink_probe: FAIL dump did not terminate with NLMSG_DONE (links=%d)\n", links); return 1; }
    if (links < 1) { printf("rtlink_probe: FAIL no interfaces in dump\n"); return 1; }
    if (named < links) { printf("rtlink_probe: FAIL %d/%d links lack IFLA_IFNAME\n", named, links); return 1; }

    printf("rtlink_probe: PASS RTM_GETLINK dump %d links, NLMSG_DONE ok\n", links);
    return 0;
}
