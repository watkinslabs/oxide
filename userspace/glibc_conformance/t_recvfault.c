/* Receive copy-fault transactions over REAL user memory: what a receive
 * reports when the caller's payload, address, ancillary or header buffer
 * cannot be written, what is consumed by that receive, and what a batch does
 * with the entry it could not deliver. Every case is privilege-independent,
 * so the guest frame must match the host oracle byte for byte whatever uid
 * runs it. Page size is read at run time and never printed. */
#define _GNU_SOURCE
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static long page;
/* Two pages: the first writable, the second unreadable and unwritable. A
 * pointer into the first that runs past its end is a copy that faults partway. */
static char *guard;
/* A whole unwritable page, for the "not one byte can land" cases. */
static char *dead;

static void report(const char *name, ssize_t rc, int saved)
{
    printf("%s rc=%d errno=%d\n", name, rc < 0 ? -1 : (int)rc, rc < 0 ? saved : 0);
}

static void report_msg(const char *name, ssize_t rc, int saved, struct msghdr *msg)
{
    printf("%s rc=%d errno=%d controllen=%d flags=0x%x\n", name, rc < 0 ? -1 : (int)rc,
           rc < 0 ? saved : 0, rc < 0 ? -1 : (int)msg->msg_controllen,
           rc < 0 ? 0u : (unsigned)msg->msg_flags);
}

static int arena(void)
{
    page = sysconf(_SC_PAGESIZE);
    guard = mmap(NULL, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    dead = mmap(NULL, page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (guard == MAP_FAILED || dead == MAP_FAILED) return -1;
    return mprotect(guard + page, page, PROT_NONE);
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

/* Send `len` bytes and wait for them to be queued, so every receive below is
 * deterministic without a timeout. */
static int deliver(int tx, struct sockaddr_in *dst, int rx, size_t len)
{
    static char out[8192];
    int spins;
    if (sendto(tx, out, len, 0, (struct sockaddr *)dst, sizeof *dst) != (ssize_t)len) return -1;
    for (spins = 0; spins < 1000000; spins++) {
        char probe;
        ssize_t rc = recv(rx, &probe, 1, MSG_PEEK | MSG_DONTWAIT);
        if (rc >= 0) return 0;
        if (errno != EAGAIN && errno != EWOULDBLOCK) return -1;
    }
    return -1;
}

/* What is still queued after a faulting receive: EAGAIN means the record was
 * retired, a byte count means it survived. */
static void drained(const char *name, int fd)
{
    char sink[64];
    ssize_t rc;
    errno = 0;
    rc = recv(fd, sink, sizeof sink, MSG_DONTWAIT);
    report(name, rc, errno);
}

/* A datagram whose payload cannot be placed: the record is reported EFAULT and
 * retired anyway, whether nothing landed or only a prefix did. */
static void datagram_payload(void)
{
    struct sockaddr_in dst;
    struct iovec iov;
    struct msghdr msg;
    int tx, rx = udp_pair(&tx, &dst);
    ssize_t rc;

    if (rx < 0 || deliver(tx, &dst, rx, 8) != 0) return;
    memset(&msg, 0, sizeof msg);
    iov.iov_base = dead; iov.iov_len = 64;
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    errno = 0;
    rc = recvmsg(rx, &msg, 0);
    report("dgram_payload_dead", rc, errno);
    drained("dgram_payload_dead_left", rx);

    if (deliver(tx, &dst, rx, 2048) != 0) return;
    memset(&msg, 0, sizeof msg);
    iov.iov_base = guard + page - 512; iov.iov_len = 4096;
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    errno = 0;
    rc = recvmsg(rx, &msg, 0);
    report("dgram_payload_split", rc, errno);
    drained("dgram_payload_split_left", rx);

    /* A peeking receive never dequeued the record, so the fault leaves it. */
    if (deliver(tx, &dst, rx, 8) != 0) return;
    memset(&msg, 0, sizeof msg);
    iov.iov_base = dead; iov.iov_len = 64;
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    errno = 0;
    rc = recvmsg(rx, &msg, MSG_PEEK);
    report("dgram_payload_peek", rc, errno);
    drained("dgram_payload_peek_left", rx);
    close(tx); close(rx);
}

/* An address buffer that cannot be written fails the receive after the payload
 * has already been placed, and the datagram stays consumed. */
static void datagram_name(void)
{
    struct sockaddr_in dst;
    struct iovec iov;
    struct msghdr msg;
    char buf[64];
    int tx, rx = udp_pair(&tx, &dst);
    ssize_t rc;

    if (rx < 0 || deliver(tx, &dst, rx, 8) != 0) return;
    memset(&msg, 0, sizeof msg);
    iov.iov_base = buf; iov.iov_len = sizeof buf;
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    msg.msg_name = dead; msg.msg_namelen = 128;
    errno = 0;
    rc = recvmsg(rx, &msg, 0);
    report("dgram_name_dead", rc, errno);
    drained("dgram_name_dead_left", rx);

    /* The header itself unwritable: same answer, one step later. */
    if (deliver(tx, &dst, rx, 8) != 0) return;
    errno = 0;
    rc = recvmsg(rx, (struct msghdr *)dead, 0);
    report("dgram_hdr_dead", rc, errno);
    drained("dgram_hdr_dead_left", rx);
    close(tx); close(rx);
}

/* An ancillary buffer that cannot be written does NOT fail the receive: the
 * entries that landed keep their space and the caller still gets its bytes. */
static void datagram_control(void)
{
    struct sockaddr_in dst;
    struct iovec iov;
    struct msghdr msg;
    char buf[64];
    int tx, rx = udp_pair(&tx, &dst), on = 1;
    ssize_t rc;

    if (rx < 0) return;
    setsockopt(rx, IPPROTO_IP, IP_PKTINFO, &on, sizeof on);
    setsockopt(rx, IPPROTO_IP, IP_RECVTTL, &on, sizeof on);
    if (deliver(tx, &dst, rx, 8) != 0) return;
    memset(&msg, 0, sizeof msg);
    iov.iov_base = buf; iov.iov_len = sizeof buf;
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    msg.msg_control = dead; msg.msg_controllen = 256;
    errno = 0;
    rc = recvmsg(rx, &msg, 0);
    report_msg("dgram_control_dead", rc, errno, &msg);

    /* The first entry fits in the mapped page, the second starts past it: the
     * published length is exactly the prefix that landed. */
    if (deliver(tx, &dst, rx, 8) != 0) return;
    memset(&msg, 0, sizeof msg);
    iov.iov_base = buf; iov.iov_len = sizeof buf;
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    msg.msg_control = guard + page - CMSG_SPACE(sizeof(struct in_pktinfo));
    msg.msg_controllen = 256;
    errno = 0;
    rc = recvmsg(rx, &msg, 0);
    report_msg("dgram_control_split", rc, errno, &msg);
    close(tx); close(rx);
}

/* A stream consumes exactly what it copied: a fault with a prefix already
 * placed reports the prefix and leaves the rest queued; a fault with nothing
 * placed reports EFAULT and consumes nothing. */
static void stream_payload(void)
{
    static char out[8192];
    struct iovec iov;
    struct msghdr msg;
    int sv[2];
    ssize_t rc;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return;
    if (send(sv[0], out, 4096, 0) != 4096) return;
    memset(&msg, 0, sizeof msg);
    iov.iov_base = guard + page - 1024; iov.iov_len = 4096;
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    errno = 0;
    rc = recvmsg(sv[1], &msg, 0);
    report("stream_payload_split", rc, errno);
    drained("stream_payload_split_left", sv[1]);

    if (send(sv[0], out, 64, 0) != 64) return;
    memset(&msg, 0, sizeof msg);
    iov.iov_base = dead; iov.iov_len = 64;
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    errno = 0;
    rc = recvmsg(sv[1], &msg, 0);
    report("stream_payload_dead", rc, errno);
    drained("stream_payload_dead_left", sv[1]);
    close(sv[0]); close(sv[1]);
}

/* A batch reports the count it delivered and latches the entry's failure as
 * the socket's pending error — except when nothing was delivered, where the
 * failure IS the answer and nothing is latched. */
static void batch_faults(void)
{
    struct sockaddr_in dst;
    struct mmsghdr entries[2];
    struct iovec iov[2];
    char buf[64];
    int tx, rx = udp_pair(&tx, &dst), value = 0;
    socklen_t len = sizeof value;
    ssize_t rc;

    if (rx < 0) return;
    if (deliver(tx, &dst, rx, 8) != 0 || deliver(tx, &dst, rx, 8) != 0) return;
    memset(entries, 0, sizeof entries);
    iov[0].iov_base = buf; iov[0].iov_len = sizeof buf;
    iov[1].iov_base = dead; iov[1].iov_len = 64;
    entries[0].msg_hdr.msg_iov = &iov[0]; entries[0].msg_hdr.msg_iovlen = 1;
    entries[1].msg_hdr.msg_iov = &iov[1]; entries[1].msg_hdr.msg_iovlen = 1;
    errno = 0;
    rc = recvmmsg(rx, entries, 2, MSG_DONTWAIT, NULL);
    report("mmsg_tail_faults", rc, errno);
    getsockopt(rx, SOL_SOCKET, SO_ERROR, &value, &len);
    printf("mmsg_tail_faults_pending errno=%d\n", value);
    drained("mmsg_tail_faults_left", rx);

    if (deliver(tx, &dst, rx, 8) != 0 || deliver(tx, &dst, rx, 8) != 0) return;
    memset(entries, 0, sizeof entries);
    iov[0].iov_base = dead; iov[0].iov_len = 64;
    iov[1].iov_base = buf; iov[1].iov_len = sizeof buf;
    entries[0].msg_hdr.msg_iov = &iov[0]; entries[0].msg_hdr.msg_iovlen = 1;
    entries[1].msg_hdr.msg_iov = &iov[1]; entries[1].msg_hdr.msg_iovlen = 1;
    errno = 0;
    rc = recvmmsg(rx, entries, 2, MSG_DONTWAIT, NULL);
    report("mmsg_head_faults", rc, errno);
    value = 0; len = sizeof value;
    getsockopt(rx, SOL_SOCKET, SO_ERROR, &value, &len);
    printf("mmsg_head_faults_pending errno=%d\n", value);
    drained("mmsg_head_faults_left", rx);
    close(tx); close(rx);
}

int main(void)
{
    if (arena() != 0) { printf("arena unavailable\n"); return 0; }
    datagram_payload();
    datagram_name();
    datagram_control();
    stream_payload();
    batch_faults();
    return 0;
}
