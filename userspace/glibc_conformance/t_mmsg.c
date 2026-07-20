/* Linux mmsg ordering corpus; output is compared verbatim by N22. */
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

static size_t batch_cap(void) {
    return UIO_MAXIOV;
}

static void base_batch(void) {
    int sv[2];
    char *m0 = "hello", *m1 = "world", b0[8] = {0}, b1[8] = {0};
    struct iovec iv[2] = {{m0, 5}, {m1, 5}}, riv[2] = {{b0, 8}, {b1, 8}};
    struct mmsghdr out[2] = {0}, in[2] = {0};
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) { puts("base=nopair"); return; }
    out[0].msg_hdr.msg_iov = &iv[0]; out[0].msg_hdr.msg_iovlen = 1;
    out[1].msg_hdr.msg_iov = &iv[1]; out[1].msg_hdr.msg_iovlen = 1;
    int sent = sendmmsg(sv[0], out, 2, 0);
    in[0].msg_hdr.msg_iov = &riv[0]; in[0].msg_hdr.msg_iovlen = 1;
    in[1].msg_hdr.msg_iov = &riv[1]; in[1].msg_hdr.msg_iovlen = 1;
    int got = recvmmsg(sv[1], in, 2, 0, NULL);
    printf("base sent=%d got=%d len=%u,%u data=%d,%d\n", sent, got, in[0].msg_len,
        in[1].msg_len, memcmp(b0, "hello", 5) == 0, memcmp(b1, "world", 5) == 0);
    close(sv[0]); close(sv[1]);
}

static void timeout_before_fd(void) {
    long page = sysconf(_SC_PAGESIZE);
    void *bad = mmap(NULL, (size_t)page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    errno = 0;
    int got = recvmmsg(-1, NULL, 0, 0, bad == MAP_FAILED ? (void *)1 : bad);
    printf("recv_timeout_before_fd rc=%d errno=%d\n", got, errno);
    if (bad != MAP_FAILED) munmap(bad, (size_t)page);
}

static void send_cap(void) {
    int sv[2];
    long page = sysconf(_SC_PAGESIZE);
    size_t cap = batch_cap();
    if (page <= 0) { puts("send_cap=unsupported"); return; }
    size_t used = cap * sizeof(struct mmsghdr);
    size_t guard = (used + (size_t)page - 1U) / (size_t)page * (size_t)page;
    size_t bytes = guard + (size_t)page;
    struct mmsghdr *msgs = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0 || msgs == MAP_FAILED ||
        mprotect((char *)msgs + guard, (size_t)page, PROT_NONE) != 0) {
        puts("send_cap=setup_failed"); return;
    }
    errno = 0;
    int got = sendmmsg(sv[0], msgs, cap + 1U, 0);
    printf("send_cap rc=%d errno=%d\n", got, errno);
    munmap(msgs, bytes); close(sv[0]); close(sv[1]);
}

static void prefix_faults(void) {
    int sv[2];
    char sent[] = "x", received[2] = {0};
    struct iovec out_iov = {sent, 1}, in_iov = {received, sizeof received};
    struct mmsghdr out[2] = {0}, in[2] = {0};
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) { puts("prefix=nopair"); return; }
    out[0].msg_hdr.msg_iov = &out_iov; out[0].msg_hdr.msg_iovlen = 1;
    out[1].msg_hdr.msg_iov = (void *)1; out[1].msg_hdr.msg_iovlen = 1;
    errno = 0;
    int send_rc = sendmmsg(sv[0], out, 2, 0), send_errno = errno;
    in[0].msg_hdr.msg_iov = &in_iov; in[0].msg_hdr.msg_iovlen = 1;
    in[1].msg_hdr.msg_iov = (void *)1; in[1].msg_hdr.msg_iovlen = 1;
    errno = 0;
    int recv_rc = recvmmsg(sv[1], in, 2, MSG_DONTWAIT, NULL), recv_errno = errno;
    printf("prefix send=%d errno=%d len=%u recv=%d errno=%d len=%u data=%d\n", send_rc,
        send_errno, out[0].msg_len, recv_rc, recv_errno, in[0].msg_len, received[0] == 'x');
    close(sv[0]); close(sv[1]);
}

static void recv_over_cap(void) {
    int sv[2];
    char sent[] = "z", received[2] = {0};
    struct iovec out_iov = {sent, 1}, in_iov = {received, sizeof received};
    size_t cap = batch_cap();
    struct mmsghdr *in = calloc(cap + 1U, sizeof(*in));
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0 || in == NULL) { puts("recv_cap=setup_failed"); return; }
    struct mmsghdr out = {0}; out.msg_hdr.msg_iov = &out_iov; out.msg_hdr.msg_iovlen = 1;
    (void)sendmmsg(sv[0], &out, 1, 0);
    in[0].msg_hdr.msg_iov = &in_iov; in[0].msg_hdr.msg_iovlen = 1;
    errno = 0;
    int got = recvmmsg(sv[1], in, cap + 1U, MSG_DONTWAIT, NULL);
    printf("recv_cap rc=%d errno=%d len=%u data=%d\n", got, errno, in[0].msg_len, received[0] == 'z');
    free(in); close(sv[0]); close(sv[1]);
}

static void nonblocking_timeout(void) {
    int sv[2];
    char sent[] = "t", received[2] = {0};
    struct iovec out_iov = {sent, 1}, in_iov = {received, sizeof received};
    struct mmsghdr out = {0}, in = {0};
    struct timespec timeout = { .tv_sec = 1, .tv_nsec = 0 };
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) { puts("nonblock=nopair"); return; }
    errno = 0;
    int got = recvmmsg(sv[1], &in, 1, MSG_DONTWAIT, &timeout);
    printf("nonblock_empty rc=%d errno=%d unchanged=%d\n", got, errno,
        timeout.tv_sec == 1 && timeout.tv_nsec == 0);
    out.msg_hdr.msg_iov = &out_iov; out.msg_hdr.msg_iovlen = 1;
    (void)sendmmsg(sv[0], &out, 1, 0);
    in.msg_hdr.msg_iov = &in_iov; in.msg_hdr.msg_iovlen = 1;
    timeout.tv_sec = 1; timeout.tv_nsec = 0;
    errno = 0;
    got = recvmmsg(sv[1], &in, 1, MSG_DONTWAIT, &timeout);
    printf("nonblock_success rc=%d errno=%d changed=%d data=%d\n", got, errno,
        timeout.tv_sec < 1, received[0] == 't');
    close(sv[0]); close(sv[1]);
}

int main(void) {
    base_batch(); timeout_before_fd(); send_cap(); prefix_faults(); recv_over_cap(); nonblocking_timeout();
    return 0;
}
