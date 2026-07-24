/* Linux rows 46/47 sendmsg/recvmsg corpus; compared verbatim by N09/N10. */
#define _GNU_SOURCE
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void r(const char *label, long rc) {
    printf("%s rc=%ld errno=%d\n", label, rc < 0 ? -1 : rc, rc < 0 ? errno : 0);
}

static int bound_udp(struct sockaddr_in *addr) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    socklen_t len = sizeof(*addr);
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || bind(fd, (struct sockaddr *)addr, sizeof(*addr)) != 0
        || getsockname(fd, (struct sockaddr *)addr, &len) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    return fd;
}

int main(void) {
    struct sockaddr_in aa, ba;
    int a = bound_udp(&aa);
    int b = bound_udp(&ba);
    if (a < 0 || b < 0) { puts("setup=failed"); return 0; }

    /* sendmsg with a two-segment scatter-gather payload "foo"+"bar". */
    struct iovec sv[2] = {
        { .iov_base = "foo", .iov_len = 3 },
        { .iov_base = "bar", .iov_len = 3 },
    };
    struct msghdr smsg;
    memset(&smsg, 0, sizeof(smsg));
    smsg.msg_name = &ba;
    smsg.msg_namelen = sizeof(ba);
    smsg.msg_iov = sv;
    smsg.msg_iovlen = 2;
    r("sendmsg", sendmsg(a, &smsg, 0));

    /* recvmsg into two segments; verify reassembly, the source address is
       written back with its real length, and msg_flags is cleared. */
    char p0[4] = {0}, p1[4] = {0};
    struct iovec rv[2] = {
        { .iov_base = p0, .iov_len = 3 },
        { .iov_base = p1, .iov_len = 3 },
    };
    struct sockaddr_in from;
    struct msghdr rmsg;
    memset(&rmsg, 0, sizeof(rmsg));
    memset(&from, 0, sizeof(from));
    rmsg.msg_name = &from;
    rmsg.msg_namelen = sizeof(from);
    rmsg.msg_iov = rv;
    rmsg.msg_iovlen = 2;
    ssize_t n = recvmsg(b, &rmsg, 0);
    printf("recvmsg n=%zd data=%.3s%.3s namelen=%u from_is_a=%d flags=%d\n",
        n, p0, p1, (unsigned)rmsg.msg_namelen,
        from.sin_port == aa.sin_port, rmsg.msg_flags);

    /* A short recvmsg buffer sets MSG_TRUNC in msg_flags (with MSG_TRUNC
       requested, the return is the true length). */
    struct iovec one = { .iov_base = "put", .iov_len = 3 };
    struct msghdr s2;
    memset(&s2, 0, sizeof(s2));
    s2.msg_name = &ba; s2.msg_namelen = sizeof(ba);
    s2.msg_iov = &one; s2.msg_iovlen = 1;
    sendmsg(a, &s2, 0);

    char sbuf[2] = {0};
    struct iovec rsmall = { .iov_base = sbuf, .iov_len = 1 };
    struct msghdr r2;
    memset(&r2, 0, sizeof(r2));
    r2.msg_iov = &rsmall; r2.msg_iovlen = 1;
    ssize_t tn = recvmsg(b, &r2, MSG_TRUNC);
    printf("recvmsg_trunc n=%zd ctrunc_or_trunc=%d\n", tn,
        (r2.msg_flags & MSG_TRUNC) ? 1 : 0);

    /* sendmsg with msg_namelen > 128: Linux __copy_msghdr clamps to
       sockaddr_storage and sends (not EINVAL); the address parser reads only
       the AF_INET struct from the clamped prefix. */
    struct iovec ivn = { .iov_base = "n", .iov_len = 1 };
    struct msghdr sn;
    memset(&sn, 0, sizeof(sn));
    sn.msg_name = &ba; sn.msg_namelen = 130; sn.msg_iov = &ivn; sn.msg_iovlen = 1;
    errno = 0; r("sendmsg_namelen130", sendmsg(a, &sn, 0));
    /* Drain it so it does not perturb later counts. */
    { char d[4]; recv(b, d, sizeof(d), MSG_DONTWAIT); }

    /* sendmsg with msg_iovlen above UIO_MAXIOV (1024): EMSGSIZE. */
    struct iovec big = { .iov_base = "z", .iov_len = 1 };
    struct msghdr sbig;
    memset(&sbig, 0, sizeof(sbig));
    sbig.msg_name = &ba; sbig.msg_namelen = sizeof(ba);
    sbig.msg_iov = &big; sbig.msg_iovlen = 1025;
    errno = 0; r("sendmsg_iov_overflow", sendmsg(a, &sbig, 0));

    /* sendmsg bad fd: EBADF. */
    errno = 0; r("sendmsg_badfd", sendmsg(-1, &smsg, 0));
    /* recvmsg bad fd: EBADF. */
    errno = 0; r("recvmsg_badfd", recvmsg(-1, &rmsg, 0));

    close(a); close(b);
    return 0;
}
