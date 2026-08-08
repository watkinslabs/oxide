/* Per-family sendmsg ancillary and destination answers; output is compared
 * verbatim against the host oracle. Every case here is privilege-independent,
 * so the guest frame must match byte for byte whatever uid runs it. */
#define _GNU_SOURCE
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

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

static int udp_pair(int *tx, struct sockaddr_in *dst)
{
    socklen_t len = sizeof *dst;
    int rx = socket(AF_INET, SOCK_DGRAM, 0);
    memset(dst, 0, sizeof *dst);
    dst->sin_family = AF_INET;
    dst->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (rx < 0 || bind(rx, (struct sockaddr *)dst, sizeof *dst) != 0 ||
        getsockname(rx, (struct sockaddr *)dst, &len) != 0) return -1;
    *tx = socket(AF_INET, SOCK_DGRAM, 0);
    return *tx < 0 ? -1 : rx;
}

/* WHICH ancillary rule a datagram socket runs: its own level's unknown type is
 * refused, a level it does not own is stepped over, and the descriptor type
 * every other family refuses is stepped over here. */
static void udp_ancillary(void)
{
    struct sockaddr_in dst;
    struct msghdr msg;
    struct iovec iov = { (void *)"x", 1 };
    int tx, rx = udp_pair(&tx, &dst), fd = 0, value;
    if (rx < 0) { puts("udp=nosock"); return; }

    value = 7;
    one_cmsg(&msg, &iov, IPPROTO_IP, IP_TTL, &value, sizeof value);
    msg.msg_name = &dst; msg.msg_namelen = sizeof dst;
    errno = 0;
    { ssize_t rc = sendmsg(tx, &msg, 0); report("udp_ttl", rc, errno); }

    value = 0;
    one_cmsg(&msg, &iov, IPPROTO_IP, IP_TTL, &value, sizeof value);
    msg.msg_name = &dst; msg.msg_namelen = sizeof dst;
    errno = 0;
    { ssize_t rc = sendmsg(tx, &msg, 0); report("udp_ttl_zero", rc, errno); }

    value = 0x10;
    one_cmsg(&msg, &iov, IPPROTO_IP, IP_TOS, &value, sizeof value);
    msg.msg_name = &dst; msg.msg_namelen = sizeof dst;
    errno = 0;
    { ssize_t rc = sendmsg(tx, &msg, 0); report("udp_tos", rc, errno); }

    one_cmsg(&msg, &iov, IPPROTO_IP, IP_TOS, control, 3);
    msg.msg_name = &dst; msg.msg_namelen = sizeof dst;
    errno = 0;
    { ssize_t rc = sendmsg(tx, &msg, 0); report("udp_tos_short", rc, errno); }

    one_cmsg(&msg, &iov, IPPROTO_IP, 250, &value, sizeof value);
    msg.msg_name = &dst; msg.msg_namelen = sizeof dst;
    errno = 0;
    { ssize_t rc = sendmsg(tx, &msg, 0); report("udp_ip_unknown", rc, errno); }

    one_cmsg(&msg, &iov, SOL_SOCKET, 250, &value, sizeof value);
    msg.msg_name = &dst; msg.msg_namelen = sizeof dst;
    errno = 0;
    { ssize_t rc = sendmsg(tx, &msg, 0); report("udp_sock_unknown", rc, errno); }

    one_cmsg(&msg, &iov, SOL_SOCKET, SCM_RIGHTS, &fd, sizeof fd);
    msg.msg_name = &dst; msg.msg_namelen = sizeof dst;
    errno = 0;
    { ssize_t rc = sendmsg(tx, &msg, 0); report("udp_rights", rc, errno); }

    /* A level no transport on this socket owns is stepped over. */
    one_cmsg(&msg, &iov, IPPROTO_IPV6, 250, &value, sizeof value);
    msg.msg_name = &dst; msg.msg_namelen = sizeof dst;
    errno = 0;
    { ssize_t rc = sendmsg(tx, &msg, 0); report("udp_other_level", rc, errno); }

    errno = 0;
    { ssize_t rc = sendto(tx, "x", 1, MSG_OOB, (struct sockaddr *)&dst, sizeof dst); report("udp_oob", rc, errno); }
    close(tx); close(rx);
}

/* An AF_UNIX stream steps over a level it does not own and refuses an unknown
 * type at the socket level. */
static void stream_ancillary(void)
{
    struct msghdr msg;
    struct iovec iov = { (void *)"x", 1 };
    int sv[2], value = 7;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { puts("tcp=nopair"); return; }
    one_cmsg(&msg, &iov, IPPROTO_IP, IP_TTL, &value, sizeof value);
    errno = 0;
    { ssize_t rc = sendmsg(sv[0], &msg, 0); report("stream_ip_level", rc, errno); }
    one_cmsg(&msg, &iov, SOL_SOCKET, 250, &value, sizeof value);
    errno = 0;
    { ssize_t rc = sendmsg(sv[0], &msg, 0); report("stream_sock_unknown", rc, errno); }
    close(sv[0]); close(sv[1]);
}

/* A byte stream refuses a destination and the refusal names its connection
 * state; a seqpacket discards `msg_namelen` and never looks. */
static void unix_destinations(void)
{
    struct sockaddr_un addr;
    struct msghdr msg;
    struct iovec iov = { (void *)"x", 1 };
    int sv[2], fresh;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path + 1, "oxide-cmsgfam");

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { puts("unix=nopair"); return; }
    memset(&msg, 0, sizeof msg);
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    msg.msg_name = &addr; msg.msg_namelen = sizeof addr;
    errno = 0;
    { ssize_t rc = sendmsg(sv[0], &msg, 0); report("stream_named", rc, errno); }
    close(sv[0]); close(sv[1]);

    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) != 0) { puts("seq=nopair"); return; }
    memset(&msg, 0, sizeof msg);
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    msg.msg_name = &addr; msg.msg_namelen = sizeof addr;
    errno = 0;
    { ssize_t rc = sendmsg(sv[0], &msg, 0); report("seqpacket_named", rc, errno); }
    close(sv[0]); close(sv[1]);

    fresh = socket(AF_UNIX, SOCK_STREAM, 0);
    errno = 0;
    { ssize_t rc = send(fresh, "x", 1, 0); report("stream_unconnected", rc, errno); }
    errno = 0;
    { ssize_t rc = sendto(fresh, "x", 1, 0, (struct sockaddr *)&addr, sizeof addr); report("stream_unconnected_named", rc, errno); }
    close(fresh);

    fresh = socket(AF_UNIX, SOCK_DGRAM, 0);
    errno = 0;
    { ssize_t rc = send(fresh, "x", 1, 0); report("dgram_unconnected", rc, errno); }
    close(fresh);
}

int main(void)
{
    udp_ancillary();
    stream_ancillary();
    unix_destinations();
    return 0;
}
