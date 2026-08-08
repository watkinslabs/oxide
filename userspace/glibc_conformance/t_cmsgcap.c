/* Capability-gated SOL_SOCKET send-ancillary types on an IPv4 datagram socket,
 * answered WITHOUT CAP_NET_RAW/CAP_NET_ADMIN. The manifest pins this probe to
 * uid=unprivileged on both sides, so the host oracle and the guest run under
 * the same privilege and the comparison is byte-exact.
 *
 * Pinned here: SO_MARK consults the capability BEFORE its width, SO_PRIORITY
 * consults its width BEFORE the capability, the interactive band is admitted
 * without any capability and anything outside it is refused, and the types
 * gated on per-socket state (SCM_TXTIME, SCM_TS_OPT_ID) are refused for the
 * missing state rather than the missing capability.
 *
 * `t_cmsgcap_priv` is the same case list under uid=root; the pair is the
 * refused/admitted differential for one surface. */
#define _GNU_SOURCE
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* An out-of-band SO_PRIORITY value: the unprivileged band is 0..6. */
#define PRIO_ABOVE_BAND 7
#define PRIO_TC_MAX 15

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

static void one_case(int tx, struct sockaddr_in *dst, const char *name, int type,
                     const void *data, size_t len)
{
    struct msghdr msg;
    struct iovec iov = { (void *)"x", 1 };
    ssize_t rc;
    one_cmsg(&msg, &iov, SOL_SOCKET, type, data, len);
    msg.msg_name = dst;
    msg.msg_namelen = sizeof *dst;
    errno = 0;
    rc = sendmsg(tx, &msg, 0);
    report(name, rc, errno);
}

int main(void)
{
    struct sockaddr_in dst;
    unsigned int word;
    unsigned long long wide = 0;
    struct ucred cred;
    int tx, rx = udp_pair(&tx, &dst);
    if (rx < 0) { puts("sockcap=nosock"); return 0; }

    /* A plain send with no ancillary: the baseline this socket answers, so a
     * difference in the cases below is the ancillary rule and not the path. */
    errno = 0;
    { ssize_t rc = sendto(tx, "x", 1, 0, (struct sockaddr *)&dst, sizeof dst);
      report("plain", rc, errno); }

    word = 0x11;
    one_case(tx, &dst, "mark", SO_MARK, &word, sizeof word);
    one_case(tx, &dst, "mark_short", SO_MARK, &word, sizeof(unsigned short));
    one_case(tx, &dst, "mark_long", SO_MARK, &wide, sizeof wide);

    word = 0;
    one_case(tx, &dst, "prio_zero", SO_PRIORITY, &word, sizeof word);
    word = 6;
    one_case(tx, &dst, "prio_band_top", SO_PRIORITY, &word, sizeof word);
    word = PRIO_ABOVE_BAND;
    one_case(tx, &dst, "prio_above_band", SO_PRIORITY, &word, sizeof word);
    one_case(tx, &dst, "prio_above_band_short", SO_PRIORITY, &word, sizeof(unsigned short));
    word = PRIO_TC_MAX;
    one_case(tx, &dst, "prio_tc_max", SO_PRIORITY, &word, sizeof word);
    word = 0xffffffffu;
    one_case(tx, &dst, "prio_wrapped", SO_PRIORITY, &word, sizeof word);
    word = 0;
    one_case(tx, &dst, "prio_long", SO_PRIORITY, &wide, sizeof wide);

    /* Gated on per-socket state, not on a capability. */
    one_case(tx, &dst, "txtime", SCM_TXTIME, &wide, sizeof wide);
    one_case(tx, &dst, "txtime_short", SCM_TXTIME, &word, sizeof word);
    one_case(tx, &dst, "ts_opt_id", SCM_TS_OPT_ID, &word, sizeof word);

    /* Carried by SOL_UNIX semantics: stepped over by every other transport. */
    memset(&cred, 0, sizeof cred);
    one_case(tx, &dst, "credentials", SCM_CREDENTIALS, &cred, sizeof cred);

    close(tx);
    close(rx);
    return 0;
}
