/* The SOL_IPV6 send-ancillary level on an AF_INET6 datagram socket, answered
 * WITH CAP_NET_RAW. The manifest pins this probe to uid=root on both sides, so
 * the host oracle runs privileged too and the comparison is byte-exact.
 *
 * Same case list as `t_cmsgv6`; the pair is the refused/admitted differential
 * for this level. Privilege admits the extension-header types (hop-by-hop,
 * destination options, routing-header destination options) whose unprivileged
 * answer is a capability refusal, and leaves every width, range and
 * unknown-type answer unchanged.
 *
 * Keep the case list identical to `t_cmsgv6`: the value of the pair is that
 * every case has both answers. */
#define _GNU_SOURCE
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Not exported by <netinet/in.h>; the level's flow-information type. */
#define OXIDE_IPV6_FLOWINFO 11
/* An unassigned type at whichever level a case names. */
#define OXIDE_CMSG_TYPE_UNKNOWN 250
/* A routing header type the level does not accept. */
#define OXIDE_RTHDR_TYPE_UNACCEPTED 0
/* IPv6 extension headers are counted in 8-byte units including the first. */
#define OXIDE_EXTHDR_UNIT 8

static char control[256];

static void report(const char *name, ssize_t rc, int saved)
{
    printf("%s rc=%d errno=%d\n", name, rc < 0 ? -1 : (int)rc, rc < 0 ? saved : 0);
}

/* One cmsg of `len` payload bytes at the head of the control buffer. */
static struct msghdr *one_cmsg(struct msghdr *msg, struct iovec *iov, int level, int type,
                               const void *data, size_t len)
{
    struct cmsghdr *cmsg;
    memset(control, 0, sizeof control);
    memset(msg, 0, sizeof *msg);
    msg->msg_iov = iov;
    msg->msg_iovlen = 1;
    msg->msg_control = control;
    msg->msg_controllen = CMSG_SPACE(len);
    cmsg = CMSG_FIRSTHDR(msg);
    cmsg->cmsg_level = level;
    cmsg->cmsg_type = type;
    cmsg->cmsg_len = CMSG_LEN(len);
    if (len) memcpy(CMSG_DATA(cmsg), data, len);
    return msg;
}

static int udp6_pair(int *tx, struct sockaddr_in6 *dst)
{
    socklen_t len = sizeof *dst;
    int rx = socket(AF_INET6, SOCK_DGRAM, 0);
    memset(dst, 0, sizeof *dst);
    dst->sin6_family = AF_INET6;
    dst->sin6_addr = in6addr_loopback;
    if (rx < 0 || bind(rx, (struct sockaddr *)dst, sizeof *dst) != 0 ||
        getsockname(rx, (struct sockaddr *)dst, &len) != 0) return -1;
    *tx = socket(AF_INET6, SOCK_DGRAM, 0);
    return *tx < 0 ? -1 : rx;
}

static int TX;
static struct sockaddr_in6 DST;

static void at_level(const char *name, int level, int type, const void *data, size_t len)
{
    struct msghdr msg;
    struct iovec iov = { (void *)"x", 1 };
    ssize_t rc;
    one_cmsg(&msg, &iov, level, type, data, len);
    msg.msg_name = &DST;
    msg.msg_namelen = sizeof DST;
    errno = 0;
    rc = sendmsg(TX, &msg, 0);
    report(name, rc, errno);
}

static void v6(const char *name, int type, const void *data, size_t len)
{
    at_level(name, IPPROTO_IPV6, type, data, len);
}

static void v6_int(const char *name, int type, int value)
{
    v6(name, type, &value, sizeof value);
}

int main(void)
{
    struct in6_pktinfo info;
    /* nexthdr, hdrlen, then type-specific bytes; hdrlen counts further units. */
    unsigned char opt[OXIDE_EXTHDR_UNIT];
    unsigned char rth[OXIDE_EXTHDR_UNIT];
    unsigned int word = 0;
    int rx, fd = 0;

    rx = udp6_pair(&TX, &DST);
    if (rx < 0) { puts("v6cmsg=nosock"); return 0; }

    /* Baseline: the datagram this socket sends with no ancillary at all. A
     * difference here is the IPv6 datagram path, not the ancillary rule. */
    errno = 0;
    { ssize_t rc = sendto(TX, "x", 1, 0, (struct sockaddr *)&DST, sizeof DST);
      report("plain", rc, errno); }

    memset(&info, 0, sizeof info);
    v6("pktinfo_any", IPV6_PKTINFO, &info, sizeof info);
    v6("pktinfo_short", IPV6_PKTINFO, &info, sizeof(unsigned int));
    info.ipi6_addr = in6addr_loopback;
    v6("pktinfo_loopback", IPV6_PKTINFO, &info, sizeof info);
    memset(&info, 0, sizeof info);
    v6("pktinfo_2292", IPV6_2292PKTINFO, &info, sizeof info);

    v6_int("hoplimit", IPV6_HOPLIMIT, 8);
    v6_int("hoplimit_default", IPV6_HOPLIMIT, -1);
    v6_int("hoplimit_below", IPV6_HOPLIMIT, -2);
    v6_int("hoplimit_above", IPV6_HOPLIMIT, 256);
    v6("hoplimit_short", IPV6_HOPLIMIT, &word, sizeof(unsigned short));
    v6("hoplimit_long", IPV6_HOPLIMIT, &info, sizeof(unsigned long long));
    v6_int("hoplimit_2292", IPV6_2292HOPLIMIT, 8);

    v6_int("tclass", IPV6_TCLASS, 0x20);
    v6_int("tclass_default", IPV6_TCLASS, -1);
    v6_int("tclass_below", IPV6_TCLASS, -2);
    v6_int("tclass_above", IPV6_TCLASS, 256);
    v6("tclass_short", IPV6_TCLASS, &word, sizeof(unsigned short));

    v6_int("dontfrag_off", IPV6_DONTFRAG, 0);
    v6_int("dontfrag_on", IPV6_DONTFRAG, 1);
    v6_int("dontfrag_bad", IPV6_DONTFRAG, 2);
    v6("dontfrag_short", IPV6_DONTFRAG, &word, sizeof(unsigned short));

    v6("flowinfo", OXIDE_IPV6_FLOWINFO, &word, sizeof word);
    v6("flowinfo_short", OXIDE_IPV6_FLOWINFO, &word, sizeof(unsigned short));

    /* Extension headers: one unit, no options beyond the header's own bytes. */
    memset(opt, 0, sizeof opt);
    v6("hopopts_short", IPV6_HOPOPTS, opt, 1);
    v6("hopopts", IPV6_HOPOPTS, opt, sizeof opt);
    opt[1] = 1; /* claims two units but only one is present */
    v6("hopopts_truncated", IPV6_HOPOPTS, opt, sizeof opt);
    opt[1] = 0;
    v6("hopopts_2292", IPV6_2292HOPOPTS, opt, sizeof opt);
    v6("dstopts", IPV6_DSTOPTS, opt, sizeof opt);
    v6("dstopts_2292", IPV6_2292DSTOPTS, opt, sizeof opt);
    v6("rthdrdstopts", IPV6_RTHDRDSTOPTS, opt, sizeof opt);

    memset(rth, 0, sizeof rth);
    rth[2] = OXIDE_RTHDR_TYPE_UNACCEPTED;
    v6("rthdr_short", IPV6_RTHDR, rth, sizeof(unsigned int));
    v6("rthdr_unaccepted_type", IPV6_RTHDR, rth, sizeof rth);
    v6("rthdr_2292", IPV6_2292RTHDR, rth, sizeof rth);

    v6("unknown_type", OXIDE_CMSG_TYPE_UNKNOWN, &word, sizeof word);

    at_level("sock_unknown", SOL_SOCKET, OXIDE_CMSG_TYPE_UNKNOWN, &word, sizeof word);
    at_level("sock_rights", SOL_SOCKET, SCM_RIGHTS, &fd, sizeof fd);
    /* A level this socket does not own is stepped over, not refused. */
    at_level("ip_level", IPPROTO_IP, IP_TTL, &word, sizeof word);

    close(TX);
    close(rx);
    return 0;
}
