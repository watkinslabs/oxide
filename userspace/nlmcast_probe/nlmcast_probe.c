// /bin/nlmcast_probe — F439 regression guard: rtnetlink multicast must be
// REAL, not a fake. Pre-F439 the kernel ignored nl_groups on bind() and had
// no NETLINK_ADD_MEMBERSHIP / rtnl_multicast, so `ip monitor` /
// systemd-networkd saw no RTM_NEW*/DEL* notifications.
//
// Asserts the Linux contract:
//   1. bind nl_groups: a NETLINK_ROUTE socket bound with
//      RTMGRP_IPV4_IFADDR receives an RTM_NEWADDR broadcast (nlmsg_pid==0,
//      kernel-originated) when an address is added.
//   2. NETLINK_ADD_MEMBERSHIP + group filtering: a second socket subscribed
//      to RTNLGRP_LINK only does NOT receive the address broadcast — proving
//      the delivery filters by group instead of broadcasting to everyone.
//
// A SIGALRM watchdog turns any unexpected park into FAIL, not a hung boot.

#define _GNU_SOURCE
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>

#ifndef AF_NETLINK
#define AF_NETLINK 16
#endif
#ifndef NETLINK_ROUTE
#define NETLINK_ROUTE 0
#endif
#define SOL_NETLINK            270
#define NETLINK_ADD_MEMBERSHIP 1
#define RTNLGRP_LINK           1
#define RTNLGRP_IPV4_IFADDR    5
#define RTMGRP_IPV4_IFADDR     0x10   /* legacy bind mask = 1<<(5-1) */
#define NLM_F_REQUEST 0x01
#define NLM_F_ACK     0x04
#define RTM_NEWADDR   20
#define IFA_LOCAL     2
#define AF_INET_      2
#undef  MSG_DONTWAIT
#define MSG_DONTWAIT  0x40

struct nlmsghdr_  { unsigned int len; unsigned short type, flags; unsigned int seq, pid; };
struct ifaddrmsg_ { unsigned char family, prefixlen, flags, scope; unsigned int index; };
struct nlattr_    { unsigned short nla_len, nla_type; };
struct sockaddr_nl_ { unsigned short nl_family, nl_pad; unsigned int nl_pid, nl_groups; };

#define PASS "nlmcast_probe: PASS\n"
static void fail(const char *why) {
    write(2, "nlmcast_probe: FAIL ", 20);
    write(2, why, strlen(why));
    write(2, "\n", 1);
    _exit(1);
}
static void on_alrm(int s) { (void)s; fail("watchdog"); }

// Scan a netlink buffer for an RTM_NEWADDR with the given pid. Returns 1 if found.
static int has_newaddr(const char *buf, int n, unsigned int want_pid) {
    int off = 0;
    while (off + (int)sizeof(struct nlmsghdr_) <= n) {
        const struct nlmsghdr_ *nh = (const struct nlmsghdr_ *)(buf + off);
        if (nh->len < sizeof(struct nlmsghdr_) || off + (int)nh->len > n) break;
        if (nh->type == RTM_NEWADDR && nh->pid == want_pid) return 1;
        off += (nh->len + 3) & ~3;
    }
    return 0;
}

int main(void) {
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alrm;
    sigaction(SIGALRM, &sa, 0);
    alarm(5);

    // (1) sub: NETLINK_ROUTE bound with nl_groups = RTMGRP_IPV4_IFADDR.
    int sub = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sub < 0) fail("socket sub");
    struct sockaddr_nl_ sa_nl; memset(&sa_nl, 0, sizeof sa_nl);
    sa_nl.nl_family = AF_NETLINK;
    sa_nl.nl_groups = RTMGRP_IPV4_IFADDR;
    if (bind(sub, (struct sockaddr *)&sa_nl, sizeof sa_nl) != 0) fail("bind nl_groups");

    // (2) other: subscribed to RTNLGRP_LINK only (must NOT see the addr msg).
    int other = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (other < 0) fail("socket other");
    int link_grp = RTNLGRP_LINK;
    if (setsockopt(other, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &link_grp, sizeof link_grp) != 0)
        fail("ADD_MEMBERSHIP");

    // Add 192.0.2.50/24 to ifindex 1 → kernel broadcasts RTM_NEWADDR.
    struct {
        struct nlmsghdr_  nh;
        struct ifaddrmsg_ ifa;
        struct nlattr_    la;
        unsigned char     addr[4];
    } req;
    memset(&req, 0, sizeof req);
    req.nh.len   = sizeof req;
    req.nh.type  = RTM_NEWADDR;
    req.nh.flags = NLM_F_REQUEST | NLM_F_ACK;
    req.nh.seq   = 1;
    req.ifa.family    = AF_INET_;
    req.ifa.prefixlen = 24;
    req.ifa.scope     = 0;
    req.ifa.index     = 1;
    req.la.nla_len  = sizeof(struct nlattr_) + 4;
    req.la.nla_type = IFA_LOCAL;
    req.addr[0] = 192; req.addr[1] = 0; req.addr[2] = 2; req.addr[3] = 50;
    if (send(sub, &req, sizeof req, 0) < 0) fail("send RTM_NEWADDR");

    // sub must receive the kernel broadcast (nlmsg_pid==0). The ack
    // (NLMSG_ERROR, pid==sub's port) may arrive in the same or a later read.
    int got_bcast = 0;
    for (int i = 0; i < 8 && !got_bcast; i++) {
        char buf[4096];
        int n = recv(sub, buf, sizeof buf, MSG_DONTWAIT);
        if (n <= 0) { if (errno == EAGAIN || errno == EWOULDBLOCK) { usleep(10000); continue; } fail("recv sub"); }
        if (has_newaddr(buf, n, 0)) got_bcast = 1;
    }
    if (!got_bcast) fail("no RTM_NEWADDR broadcast on bound socket");

    // other (link-only) must NOT have received the address broadcast.
    char obuf[4096];
    int on = recv(other, obuf, sizeof obuf, MSG_DONTWAIT);
    if (on > 0 && has_newaddr(obuf, on, 0)) fail("addr broadcast leaked to link-only socket");

    alarm(0);
    write(1, PASS, sizeof PASS - 1);
    return 0;
}
