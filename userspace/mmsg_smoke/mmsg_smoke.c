// /bin/mmsg_smoke - host-Linux differential tests for sendmmsg/recvmmsg.

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define PASS "mmsg_smoke: PASS\n"

struct udp_pair {
    int tx;
    int rx;
};

static int fail(const char *why) {
    char b[128];
    int n = snprintf(b, sizeof(b), "mmsg_smoke: FAIL %s errno=%d\n", why, errno);
    if (n > 0) (void)write(STDOUT_FILENO, b, (size_t)n);
    return 1;
}

static int pair_open(struct udp_pair *p) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    p->tx = -1;
    p->rx = socket(AF_INET, SOCK_DGRAM, 0);
    if (p->rx < 0) return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(p->rx, (struct sockaddr *)&addr, sizeof(addr)) < 0) goto error;
    if (getsockname(p->rx, (struct sockaddr *)&addr, &addr_len) < 0) goto error;

    p->tx = socket(AF_INET, SOCK_DGRAM, 0);
    if (p->tx < 0) goto error;
    if (connect(p->tx, (struct sockaddr *)&addr, addr_len) < 0) goto error;
    return 0;

error:
    {
        int saved = errno;
        if (p->tx >= 0) (void)close(p->tx);
        (void)close(p->rx);
        errno = saved;
    }
    return -1;
}

static void pair_close(struct udp_pair *p) {
    (void)close(p->tx);
    (void)close(p->rx);
}

static void recv_vec_init(struct mmsghdr *msg, struct iovec *iov,
                          char buf[][32], size_t count) {
    size_t i;

    memset(msg, 0, count * sizeof(*msg));
    for (i = 0; i < count; i++) {
        iov[i].iov_base = buf[i];
        iov[i].iov_len = sizeof(buf[i]);
        msg[i].msg_hdr.msg_iov = &iov[i];
        msg[i].msg_hdr.msg_iovlen = 1;
    }
}

static const char *test_full_batch(void) {
    static const char *const payloads[] = { "alpha", "bravo", "charlie" };
    struct udp_pair p;
    struct mmsghdr out[ARRAY_LEN(payloads)];
    struct iovec out_iov[ARRAY_LEN(payloads)];
    struct mmsghdr in[ARRAY_LEN(payloads)];
    struct iovec in_iov[ARRAY_LEN(payloads)];
    char buf[ARRAY_LEN(payloads)][32];
    size_t i;
    int rc;

    if (pair_open(&p) < 0) return "full/pair-open";
    memset(out, 0, sizeof(out));
    for (i = 0; i < ARRAY_LEN(payloads); i++) {
        out_iov[i].iov_base = (void *)payloads[i];
        out_iov[i].iov_len = strlen(payloads[i]);
        out[i].msg_hdr.msg_iov = &out_iov[i];
        out[i].msg_hdr.msg_iovlen = 1;
    }
    rc = sendmmsg(p.tx, out, (unsigned int)ARRAY_LEN(out), 0);
    if (rc != (int)ARRAY_LEN(out)) { pair_close(&p); return "full/sendmmsg"; }

    recv_vec_init(in, in_iov, buf, ARRAY_LEN(in));
    rc = recvmmsg(p.rx, in, (unsigned int)ARRAY_LEN(in), 0, NULL);
    if (rc != (int)ARRAY_LEN(in)) { pair_close(&p); return "full/count"; }
    for (i = 0; i < ARRAY_LEN(payloads); i++) {
        size_t len = strlen(payloads[i]);
        if (in[i].msg_len != len || memcmp(buf[i], payloads[i], len) != 0) {
            pair_close(&p);
            return "full/payload";
        }
    }
    pair_close(&p);
    return NULL;
}

static const char *test_zero_length(void) {
    struct udp_pair p;
    struct mmsghdr in[2];
    struct iovec iov[2];
    char buf[2][32];
    int rc;

    if (pair_open(&p) < 0) return "zero/pair-open";
    if (send(p.tx, "", 0, 0) != 0 || send(p.tx, "x", 1, 0) != 1) {
        pair_close(&p);
        return "zero/send";
    }
    recv_vec_init(in, iov, buf, ARRAY_LEN(in));
    rc = recvmmsg(p.rx, in, (unsigned int)ARRAY_LEN(in), MSG_DONTWAIT, NULL);
    if (rc != 2 || in[0].msg_len != 0 || in[1].msg_len != 1 || buf[1][0] != 'x') {
        pair_close(&p);
        return "zero/count";
    }
    pair_close(&p);
    return NULL;
}

static const char *test_waitforone(void) {
    struct udp_pair p;
    struct mmsghdr in[2];
    struct iovec iov[2];
    struct timespec timeout = { .tv_sec = 1, .tv_nsec = 0 };
    char buf[2][32];
    int rc;

    if (pair_open(&p) < 0) return "waitforone/pair-open";
    if (send(p.tx, "w", 1, 0) != 1) { pair_close(&p); return "waitforone/send"; }
    recv_vec_init(in, iov, buf, ARRAY_LEN(in));
    rc = recvmmsg(p.rx, in, (unsigned int)ARRAY_LEN(in), MSG_WAITFORONE, &timeout);
    if (rc != 1 || in[0].msg_len != 1 || buf[0][0] != 'w') {
        pair_close(&p);
        return "waitforone/count";
    }
    if (timeout.tv_sec == 0 && timeout.tv_nsec < 100000000L) {
        pair_close(&p);
        return "waitforone/blocked-later";
    }
    pair_close(&p);
    return NULL;
}

static const char *test_finite_timeout(void) {
    struct udp_pair p;
    struct mmsghdr in[2];
    struct iovec iov[2];
    struct timespec delay = { .tv_sec = 0, .tv_nsec = 100000000L };
    struct timespec timeout = { .tv_sec = 1, .tv_nsec = 0 };
    char buf[2][32];
    pid_t child;
    int status;
    int rc;

    if (pair_open(&p) < 0) return "timeout/pair-open";
    if (send(p.tx, "t", 1, 0) != 1) { pair_close(&p); return "timeout/send"; }
    child = fork();
    if (child < 0) { pair_close(&p); return "timeout/fork"; }
    if (child == 0) {
        while (nanosleep(&delay, &delay) < 0 && errno == EINTR) {}
        _exit(send(p.tx, "u", 1, 0) == 1 ? 0 : 1);
    }
    recv_vec_init(in, iov, buf, ARRAY_LEN(in));
    rc = recvmmsg(p.rx, in, (unsigned int)ARRAY_LEN(in), 0, &timeout);
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        pair_close(&p);
        return "timeout/child";
    }
    if (rc != 2 || in[0].msg_len != 1 || buf[0][0] != 't' ||
        in[1].msg_len != 1 || buf[1][0] != 'u') {
        pair_close(&p);
        return "timeout/count";
    }
    if (timeout.tv_sec != 0 || timeout.tv_nsec <= 0 || timeout.tv_nsec >= 1000000000L) {
        pair_close(&p);
        return "timeout/remaining";
    }
    pair_close(&p);
    return NULL;
}

static const char *test_invalid_timeout(void) {
    struct udp_pair p;
    struct mmsghdr in;
    struct iovec iov;
    struct timespec timeout = { .tv_sec = 0, .tv_nsec = 1000000000L };
    char buf[1][32];
    int rc;

    if (pair_open(&p) < 0) return "invalid-timeout/pair-open";
    recv_vec_init(&in, &iov, buf, 1);
    errno = 0;
    rc = recvmmsg(p.rx, &in, 1, MSG_DONTWAIT, &timeout);
    if (rc != -1 || errno != EINVAL) {
        pair_close(&p);
        return "invalid-timeout/result";
    }
    pair_close(&p);
    return NULL;
}

static const char *test_partial_nonblock(void) {
    struct udp_pair p;
    struct mmsghdr in[3];
    struct iovec iov[3];
    struct timespec timeout = { .tv_sec = 1, .tv_nsec = 0 };
    char buf[3][32];
    int rc;

    if (pair_open(&p) < 0) return "partial/pair-open";
    if (send(p.tx, "p", 1, 0) != 1) { pair_close(&p); return "partial/send"; }
    recv_vec_init(in, iov, buf, ARRAY_LEN(in));
    in[1].msg_len = UINT_MAX;
    in[2].msg_len = UINT_MAX;
    rc = recvmmsg(p.rx, in, (unsigned int)ARRAY_LEN(in), MSG_DONTWAIT, &timeout);
    if (rc != 1 || in[0].msg_len != 1 || buf[0][0] != 'p' ||
        in[1].msg_len != UINT_MAX || in[2].msg_len != UINT_MAX ||
        timeout.tv_sec != 0 || timeout.tv_nsec <= 0 || timeout.tv_nsec >= 1000000000L) {
        pair_close(&p);
        return "partial/result";
    }
    pair_close(&p);
    return NULL;
}

static const char *test_vector_ordering(void) {
    struct udp_pair p;
    struct timespec invalid = { .tv_sec = 0, .tv_nsec = 1000000000L };
    int rc;

    if (pair_open(&p) < 0) return "vector/pair-open";

    errno = 0;
    rc = recvmmsg(p.rx, NULL, 0, MSG_DONTWAIT, NULL);
    if (rc != 0) { pair_close(&p); return "vector/zero-null"; }

    errno = 0;
    rc = recvmmsg(-1, NULL, 0, MSG_DONTWAIT, NULL);
    if (rc != -1 || errno != EBADF) { pair_close(&p); return "vector/fd-before-zero"; }

    errno = 0;
    rc = recvmmsg(p.rx, NULL, UINT_MAX, MSG_DONTWAIT, NULL);
    if (rc != -1 || errno != EFAULT) { pair_close(&p); return "vector/null-before-vlen"; }

    errno = 0;
    rc = recvmmsg(p.rx, NULL, 1, MSG_DONTWAIT, NULL);
    if (rc != -1 || errno != EFAULT) { pair_close(&p); return "vector/null"; }

    errno = 0;
    rc = recvmmsg(p.rx, NULL, 0, MSG_DONTWAIT, &invalid);
    if (rc != -1 || errno != EINVAL) {
        pair_close(&p);
        return "vector/timeout-before-zero";
    }

    pair_close(&p);
    return NULL;
}

static const char *test_send_vector_ordering(void) {
    struct udp_pair p;
    struct mmsghdr out[2];
    struct iovec iov[2];
    char payload[2] = { 's', 't' };
    int rc;

    if (pair_open(&p) < 0) return "send-vector/pair-open";
    memset(out, 0, sizeof(out));
    memset(iov, 0, sizeof(iov));
    iov[0].iov_base = &payload[0];
    iov[0].iov_len = 1;
    iov[1].iov_base = &payload[1];
    iov[1].iov_len = 1;
    out[0].msg_hdr.msg_iov = &iov[0];
    out[0].msg_hdr.msg_iovlen = 1;
    out[1].msg_hdr.msg_iov = &iov[1];
    out[1].msg_hdr.msg_iovlen = 1;

    errno = 0;
    rc = sendmmsg(p.tx, NULL, 0, 0);
    if (rc != 0) { pair_close(&p); return "send-vector/zero-null"; }

    errno = 0;
    rc = sendmmsg(-1, NULL, 0, 0);
    if (rc != -1 || errno != EBADF) { pair_close(&p); return "send-vector/fd-before-zero"; }

    errno = 0;
    rc = sendmmsg(p.tx, NULL, 1, 0);
    if (rc != -1 || errno != EFAULT) { pair_close(&p); return "send-vector/null"; }

    out[1].msg_hdr.msg_iov = (struct iovec *)(uintptr_t)1;
    errno = 0;
    rc = sendmmsg(p.tx, out, 2, 0);
    if (rc != 1 || out[0].msg_len != 1) {
        pair_close(&p);
        return "send-vector/partial-efault";
    }
    if (recv(p.rx, payload, sizeof(payload), 0) != 1 || payload[0] != 's') {
        pair_close(&p);
        return "send-vector/prefix";
    }
    pair_close(&p);
    return NULL;
}

static const char *test_raw_vlen_truncation(void) {
    struct udp_pair p;
    struct mmsghdr in[2];
    struct iovec iov[2];
    char buf[2][32];
    uint64_t wide_zero = UINT64_C(1) << 32;
    long rc;

    if (pair_open(&p) < 0) return "raw-vlen/pair-open";
    if (send(p.tx, "a", 1, 0) != 1 || send(p.tx, "b", 1, 0) != 1) {
        pair_close(&p);
        return "raw-vlen/send";
    }
    recv_vec_init(in, iov, buf, ARRAY_LEN(in));
    rc = syscall(SYS_recvmmsg, p.rx, in, wide_zero, MSG_DONTWAIT, NULL);
    if (rc != 0) { pair_close(&p); return "raw-vlen/zero"; }

    rc = syscall(SYS_recvmmsg, p.rx, in, wide_zero | UINT64_C(1), MSG_DONTWAIT, NULL);
    if (rc != 1 || in[0].msg_len != 1 || buf[0][0] != 'a') {
        pair_close(&p);
        return "raw-vlen/one";
    }
    if (recv(p.rx, buf[1], sizeof(buf[1]), MSG_DONTWAIT) != 1 || buf[1][0] != 'b') {
        pair_close(&p);
        return "raw-vlen/extra-consumed";
    }
    pair_close(&p);
    return NULL;
}

static const char *test_udp_oob_dontwait(void) {
    struct udp_pair p;
    struct mmsghdr in[2];
    struct iovec iov[2];
    char buf[2][32];
    int rc;

    if (pair_open(&p) < 0) return "udp-oob/pair-open";
    if (send(p.tx, "o", 1, 0) != 1 || send(p.tx, "k", 1, 0) != 1) {
        pair_close(&p);
        return "udp-oob/send";
    }
    recv_vec_init(in, iov, buf, ARRAY_LEN(in));
    rc = recvmmsg(p.rx, in, (unsigned int)ARRAY_LEN(in),
                  MSG_OOB | MSG_DONTWAIT, NULL);
    if (rc != 2 || in[0].msg_len != 1 || buf[0][0] != 'o' ||
        in[1].msg_len != 1 || buf[1][0] != 'k') {
        pair_close(&p);
        return "udp-oob/result";
    }
    pair_close(&p);
    return NULL;
}

static const char *test_partial_efault_so_error(void) {
    struct udp_pair p;
    struct mmsghdr in[2];
    struct iovec iov[2];
    char buf[2][32];
    socklen_t error_len;
    int socket_error;
    int rc;

    if (pair_open(&p) < 0) return "partial-efault/pair-open";
    if (send(p.tx, "e", 1, 0) != 1 || send(p.tx, "f", 1, 0) != 1) {
        pair_close(&p);
        return "partial-efault/send";
    }
    recv_vec_init(in, iov, buf, ARRAY_LEN(in));
    in[1].msg_hdr.msg_iov = (struct iovec *)(uintptr_t)1;
    rc = recvmmsg(p.rx, in, (unsigned int)ARRAY_LEN(in), MSG_DONTWAIT, NULL);
    if (rc != 1 || in[0].msg_len != 1 || buf[0][0] != 'e') {
        pair_close(&p);
        return "partial-efault/result";
    }

    socket_error = 0;
    error_len = sizeof(socket_error);
    if (getsockopt(p.rx, SOL_SOCKET, SO_ERROR, &socket_error, &error_len) < 0 ||
        error_len != sizeof(socket_error) || socket_error != EFAULT) {
        pair_close(&p);
        return "partial-efault/published";
    }
    socket_error = -1;
    error_len = sizeof(socket_error);
    if (getsockopt(p.rx, SOL_SOCKET, SO_ERROR, &socket_error, &error_len) < 0 ||
        error_len != sizeof(socket_error) || socket_error != 0) {
        pair_close(&p);
        return "partial-efault/clear";
    }
    pair_close(&p);
    return NULL;
}

static int send_fd(int socket_fd, int fd, char payload) {
    union {
        max_align_t align;
        char buf[CMSG_SPACE(sizeof(int))];
    } control;
    struct iovec iov = { .iov_base = &payload, .iov_len = sizeof(payload) };
    struct msghdr msg;
    struct cmsghdr *cmsg;

    memset(&msg, 0, sizeof(msg));
    memset(&control, 0, sizeof(control));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.buf;
    msg.msg_controllen = sizeof(control.buf);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
    return sendmsg(socket_fd, &msg, 0) == 1 ? 0 : -1;
}

static const char *test_unix_rights_batch(void) {
    union control_buf {
        max_align_t align;
        char buf[CMSG_SPACE(sizeof(int))];
    } control[2];
    struct mmsghdr in[2];
    struct iovec iov[2];
    struct cmsghdr *cmsg;
    int sockets[2] = { -1, -1 };
    int pipes[2][2] = { { -1, -1 }, { -1, -1 } };
    int received[2] = { -1, -1 };
    char payload[2] = { 0, 0 };
    const char expected[2] = { 'A', 'B' };
    const char *why = NULL;
    size_t i;
    int rc;

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) < 0) return "unix-rights/socketpair";
    if (pipe(pipes[0]) < 0 || pipe(pipes[1]) < 0) {
        why = "unix-rights/pipe";
        goto out;
    }
    if (write(pipes[0][1], &expected[0], 1) != 1 ||
        write(pipes[1][1], &expected[1], 1) != 1 ||
        send_fd(sockets[0], pipes[0][0], '0') < 0 ||
        send_fd(sockets[0], pipes[1][0], '1') < 0) {
        why = "unix-rights/send";
        goto out;
    }

    memset(in, 0, sizeof(in));
    memset(control, 0, sizeof(control));
    for (i = 0; i < ARRAY_LEN(in); i++) {
        iov[i].iov_base = &payload[i];
        iov[i].iov_len = 1;
        in[i].msg_hdr.msg_iov = &iov[i];
        in[i].msg_hdr.msg_iovlen = 1;
        in[i].msg_hdr.msg_control = control[i].buf;
        in[i].msg_hdr.msg_controllen = sizeof(control[i].buf);
    }
    rc = recvmmsg(sockets[1], in, (unsigned int)ARRAY_LEN(in),
                  MSG_DONTWAIT | MSG_CMSG_CLOEXEC, NULL);
    if (rc != 2) { why = "unix-rights/count"; goto out; }

    for (i = 0; i < ARRAY_LEN(in); i++) {
        char byte = 0;

        cmsg = CMSG_FIRSTHDR(&in[i].msg_hdr);
        if (payload[i] != (char)('0' + i) || in[i].msg_len != 1 ||
            (in[i].msg_hdr.msg_flags & MSG_CTRUNC) != 0 || cmsg == NULL ||
            cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS ||
            cmsg->cmsg_len != CMSG_LEN(sizeof(int))) {
            why = "unix-rights/control";
            goto out;
        }
        memcpy(&received[i], CMSG_DATA(cmsg), sizeof(received[i]));
        if (fcntl(received[i], F_GETFD) != FD_CLOEXEC) {
            why = "unix-rights/cloexec";
            goto out;
        }
        if (read(received[i], &byte, 1) != 1 || byte != expected[i]) {
            why = "unix-rights/association";
            goto out;
        }
    }

out:
    for (i = 0; i < ARRAY_LEN(received); i++) {
        if (received[i] >= 0) (void)close(received[i]);
        if (pipes[i][0] >= 0) (void)close(pipes[i][0]);
        if (pipes[i][1] >= 0) (void)close(pipes[i][1]);
        if (sockets[i] >= 0) (void)close(sockets[i]);
    }
    return why;
}

int main(void) {
    const char *(*const tests[])(void) = {
        test_full_batch,
        test_zero_length,
        test_waitforone,
        test_finite_timeout,
        test_invalid_timeout,
        test_partial_nonblock,
        test_vector_ordering,
        test_send_vector_ordering,
        test_raw_vlen_truncation,
        test_udp_oob_dontwait,
        test_partial_efault_so_error,
        test_unix_rights_batch,
    };
    size_t i;

    for (i = 0; i < ARRAY_LEN(tests); i++) {
        const char *why = tests[i]();
        if (why != NULL) return fail(why);
    }
    (void)write(STDOUT_FILENO, PASS, sizeof(PASS) - 1);
    return 0;
}
