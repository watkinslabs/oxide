/* Linux rows 46/47 sendmsg/recvmsg corpus; compared verbatim by N09/N10. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
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

static void *guard_pair(size_t page) {
    void *p = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED || mprotect((char *)p + page, page, PROT_NONE) != 0) {
        if (p != MAP_FAILED) munmap(p, page * 2);
        return MAP_FAILED;
    }
    return p;
}

static int send_bytes(int fd, const struct sockaddr_in *to,
                      const void *data, size_t len) {
    return sendto(fd, data, len, 0, (const struct sockaddr *)to, sizeof(*to)) == (ssize_t)len;
}

static int queue_empty(int fd) {
    char c;
    errno = 0;
    return recv(fd, &c, 1, MSG_DONTWAIT) < 0 && errno == EAGAIN;
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

    /* A resolved non-socket fd is rejected before the msghdr is imported. */
    int file = open("/dev/null", O_RDONLY);
    errno = 0; r("recvmsg_file_badmsg", recvmsg(file, (struct msghdr *)1, 0));
    close(file);
    errno = 0; r("recvmsg_null_msg", recvmsg(b, NULL, MSG_DONTWAIT));

    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    void *guard = guard_pair(page);
    void *guard2 = guard_pair(page);
    void *ro = mmap(NULL, page, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (guard == MAP_FAILED || guard2 == MAP_FAILED || ro == MAP_FAILED) {
        puts("mmap=failed"); close(a); close(b); return 0;
    }

    /* Import faults happen before dequeue, including a split msghdr and a
       split iovec metadata record. */
    struct msghdr *split_hdr = (struct msghdr *)((char *)guard + page - sizeof(*split_hdr) / 2);
    memset(split_hdr, 0, sizeof(*split_hdr) / 2);
    send_bytes(a, &ba, "h", 1);
    errno = 0;
    int rc = recvmsg(b, split_hdr, MSG_DONTWAIT);
    int saved = errno;
    char kept = 0;
    int kept_n = recv(b, &kept, 1, MSG_DONTWAIT);
    printf("recvmsg_split_hdr rc=%d errno=%d preserved=%d\n",
        rc < 0 ? -1 : rc, rc < 0 ? saved : 0, kept_n == 1 && kept == 'h');

    struct iovec *split_iov = (struct iovec *)((char *)guard + page - 8);
    split_iov->iov_base = &kept;
    struct msghdr import;
    memset(&import, 0, sizeof(import));
    import.msg_iov = split_iov; import.msg_iovlen = 1;
    send_bytes(a, &ba, "i", 1);
    errno = 0;
    rc = recvmsg(b, &import, MSG_DONTWAIT);
    saved = errno;
    kept = 0; kept_n = recv(b, &kept, 1, MSG_DONTWAIT);
    printf("recvmsg_split_iov rc=%d errno=%d preserved=%d\n",
        rc < 0 ? -1 : rc, rc < 0 ? saved : 0, kept_n == 1 && kept == 'i');

    /* Payload faults retire a UDP datagram. A cross-page destination also
       detects whether a copied prefix is incorrectly reported as success. */
    struct iovec bad_iov = { .iov_base = (void *)1, .iov_len = 1 };
    struct msghdr bad_payload;
    memset(&bad_payload, 0, sizeof(bad_payload));
    bad_payload.msg_iov = &bad_iov; bad_payload.msg_iovlen = 1;
    send_bytes(a, &ba, "p", 1);
    errno = 0; rc = recvmsg(b, &bad_payload, MSG_DONTWAIT);
    saved = errno;
    printf("recvmsg_bad_payload rc=%d errno=%d consumed=%d\n",
        rc < 0 ? -1 : rc, rc < 0 ? saved : 0, queue_empty(b));

    char *split_payload = (char *)guard2 + page - 1;
    struct iovec split_payload_iov = { .iov_base = split_payload, .iov_len = 2 };
    struct msghdr split_payload_msg;
    memset(&split_payload_msg, 0, sizeof(split_payload_msg));
    split_payload_msg.msg_iov = &split_payload_iov;
    split_payload_msg.msg_iovlen = 1;
    send_bytes(a, &ba, "xy", 2);
    errno = 0; rc = recvmsg(b, &split_payload_msg, MSG_DONTWAIT);
    saved = errno;
    printf("recvmsg_split_payload rc=%d errno=%d prefix=%c consumed=%d\n",
        rc < 0 ? -1 : rc, rc < 0 ? saved : 0, split_payload[0], queue_empty(b));

    /* Output faults occur after payload dequeue. Source-length publication
       precedes the source-address copy, and flags precede controllen. */
    char named_payload = 0;
    struct iovec named_iov = { .iov_base = &named_payload, .iov_len = 1 };
    struct msghdr bad_name;
    memset(&bad_name, 0, sizeof(bad_name));
    bad_name.msg_name = (void *)1; bad_name.msg_namelen = sizeof(struct sockaddr_in);
    bad_name.msg_iov = &named_iov; bad_name.msg_iovlen = 1;
    send_bytes(a, &ba, "n", 1);
    errno = 0; rc = recvmsg(b, &bad_name, MSG_DONTWAIT);
    saved = errno;
    printf("recvmsg_bad_name rc=%d errno=%d payload=%c namelen=%u consumed=%d\n",
        rc < 0 ? -1 : rc, rc < 0 ? saved : 0, named_payload,
        (unsigned)bad_name.msg_namelen, queue_empty(b));

    char ro_payload = 0;
    struct iovec ro_iov = { .iov_base = &ro_payload, .iov_len = 1 };
    struct msghdr *ro_hdr = (struct msghdr *)ro;
    memset(ro_hdr, 0, sizeof(*ro_hdr));
    ro_hdr->msg_iov = &ro_iov; ro_hdr->msg_iovlen = 1;
    mprotect(ro, page, PROT_READ);
    send_bytes(a, &ba, "f", 1);
    errno = 0; rc = recvmsg(b, ro_hdr, MSG_DONTWAIT);
    saved = errno;
    printf("recvmsg_readonly_header rc=%d errno=%d payload=%c consumed=%d\n",
        rc < 0 ? -1 : rc, rc < 0 ? saved : 0, ro_payload, queue_empty(b));

    munmap(guard, page * 2);
    munmap(guard2, page * 2);
    munmap(ro, page);

    close(a); close(b);
    return 0;
}
