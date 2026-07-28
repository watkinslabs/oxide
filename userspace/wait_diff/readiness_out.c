/* POLLOUT under send-buffer backpressure — the other half of readiness.
 *
 * readiness.c asks whether a wakeup ever ARRIVES. This file asks the
 * inverse: whether readiness is ever WITHDRAWN. A kernel that reports
 * POLLOUT unconditionally turns every non-blocking writer into a spin
 * loop — poll says writable, write says EAGAIN, repeat — which burns a
 * core and never blocks, so it looks like a scheduler problem rather than
 * a poll problem.
 *
 * Linux: `unix_poll` masks POLLOUT off through `unix_writable(sk)`
 * (`refcount_read(&sk->sk_wmem_alloc) < READ_ONCE(sk->sk_sndbuf)`,
 * net/unix/af_unix.c) and re-asserts it from `unix_write_space` when the
 * peer's read frees the sender-charged skbs. TCP: `tcp_poll` gates on
 * `sk_stream_is_writeable` and `tcp_check_space` -> `sk_write_space`
 * re-arms it once the ACK releases the send queue (net/ipv4/tcp.c). Both
 * transitions are edge events on the SENDER's socket driven by the
 * READER's progress, which is the part a rescan-based implementation
 * cannot fake.
 *
 * `epoll_unix_out_backpressure` runs the same sequence level-triggered
 * through epoll, where the re-assert must come from `ep_poll_callback` on
 * `sk_wq` rather than from a fresh poll of the file.
 *
 * Buffers are set SMALL and explicitly so the fill loop is bounded and so
 * TCP autotuning is off (a socket with an explicit SO_{SND,RCV}BUF loses
 * SOCK_{SND,RCV}BUF_LOCK-gated growth). Sizes are never PRINTED: the two
 * kernels may legitimately round them differently, and the semantics under
 * test are the two 0/1 transitions, not the capacity.
 */
#include "probe.h"

#define RDY_CHUNK        1024
#define RDY_FILL_CAP     4096
#define RDY_FILL_SETTLE     4
#define RDY_FILL_GAP_MS    50u
#define RDY_SMALL_BUF    4096
#define RDY_DRAIN_ROUNDS    8
#define RDY_DRAIN_GAP_MS   20u

static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* 1 = the path is full and stays full, 0 = cap hit without filling,
 * -1 = error.
 *
 * A SINGLE EAGAIN is not "full" on TCP: it means the sender's write queue
 * was momentarily full while the receive window was still open, and
 * loopback then drains the queue into the peer within milliseconds — so
 * writability comes BACK with no reader involved, and the `nodrain` mutant
 * could not change the TCP record at all (measured, host oracle). Fullness
 * is only established once EAGAIN persists across RDY_FILL_SETTLE offers
 * spaced RDY_FILL_GAP_MS apart, by which point both the send buffer and
 * the peer's receive buffer are full and only a reader can free them. */
static int fill_to_eagain(int fd) {
    char buf[RDY_CHUNK];
    /* `nofill` mutant: leave the send buffer EMPTY while claiming it is
     * full, so the full-buffer poll must report POLLOUT and
     * `out_when_full` flips to 1 — the exact record a kernel that never
     * withdraws writability produces. */
    if (mutant("nofill")) return 1;
    memset(buf, 'x', sizeof buf);
    int budget = RDY_FILL_CAP;
    int settled = 0;
    while (settled < RDY_FILL_SETTLE && budget > 0) {
        ssize_t n = write(fd, buf, sizeof buf);
        budget--;
        if (n >= 0) { settled = 0; continue; }
        if (errno == EINTR) continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK) return -1;
        settled++;
        sleep_ms(RDY_FILL_GAP_MS);
    }
    return budget > 0 ? 1 : 0;
}

/* Several rounds, not one: a partially drained receive queue can leave the
 * sender still above its low-water mark, and the post-drain poll would
 * then time out for a reason that has nothing to do with the wake path. */
static void drain_all(int fd) {
    char buf[RDY_CHUNK];
    /* `nodrain` mutant: never free the peer's queue, so writability is
     * never restored and `out_after_drain` must fall to 0. */
    if (mutant("nodrain")) return;
    for (int round = 0; round < RDY_DRAIN_ROUNDS; round++) {
        for (;;) {
            ssize_t n = read(fd, buf, sizeof buf);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
        }
        sleep_ms(RDY_DRAIN_GAP_MS);
    }
}

static int poll_out_once(int fd, int timeout_ms) {
    struct pollfd p;
    p.fd = fd; p.events = POLLOUT; p.revents = 0;
    int rc = poll(&p, 1, timeout_ms);
    if (rc < 0) return -1;
    return (rc > 0 && (p.revents & POLLOUT) != 0) ? 1 : 0;
}

static int epoll_out_once(int ep, int timeout_ms) {
    struct epoll_event got;
    memset(&got, 0, sizeof got);
    int rc = epoll_wait(ep, &got, 1, timeout_ms);
    if (rc < 0) return -1;
    return (rc > 0 && (got.events & EPOLLOUT) != 0) ? 1 : 0;
}

/* Fill -> observe not-writable -> drain -> observe writable again, all in
 * one child so the post-drain wait is bounded by `wait_bounded` even if
 * the kernel parks it with no wake source. */
static void out_child(int wfd, int rfd, int use_epoll) {
    int ep = -1;
    set_nonblock(wfd);
    set_nonblock(rfd);
    if (use_epoll) {
        struct epoll_event ev;
        ep = epoll_create1(0);
        if (ep < 0) _exit(RDY_ERROR);
        memset(&ev, 0, sizeof ev);
        /* Level-triggered deliberately: EPOLLET would report the initial
         * writable edge and then say nothing, so the record could not tell
         * a withdrawn readiness from a missing re-arm. */
        ev.events = EPOLLOUT;
        ev.data.fd = wfd;
        if (epoll_ctl(ep, EPOLL_CTL_ADD, wfd, &ev) < 0) _exit(RDY_ERROR);
    }
    int filled = fill_to_eagain(wfd);
    if (filled < 0) _exit(RDY_ERROR);
    if (filled == 0) _exit(RDY_NOFILL);
    int full = use_epoll ? epoll_out_once(ep, 0) : poll_out_once(wfd, 0);
    if (full < 0) _exit(RDY_ERROR);
    drain_all(rfd);
    int after = use_epoll ? epoll_out_once(ep, (int)RDY_DRAIN_POLL_MS)
                          : poll_out_once(wfd, (int)RDY_DRAIN_POLL_MS);
    if (after < 0) _exit(RDY_ERROR);
    _exit(RDY_OK | (full ? RDY_FULL_BIT : 0) | (after ? RDY_DRAIN_BIT : 0));
}

static void out_case(const char *test, int wfd, int rfd, int use_epoll) {
    pid_t pid = fork();
    if (pid == 0) out_child(wfd, rfd, use_epoll);
    int st = 0;
    if (!wait_bounded(pid, RDY_GUARD_MS, &st)) {
        kill(pid, SIGKILL); reap(pid);
        out("ready", test, "outcome=blocked|out_when_full=0|out_after_drain=0");
        return;
    }
    if (!WIFEXITED(st)) {
        out("ready", test, "outcome=killed|out_when_full=0|out_after_drain=0");
        return;
    }
    int code = WEXITSTATUS(st);
    out("ready", test, "outcome=%s|out_when_full=%d|out_after_drain=%d",
        rdy_outcome_name(code & 7),
        (code & RDY_FULL_BIT) ? 1 : 0, (code & RDY_DRAIN_BIT) ? 1 : 0);
}

static void unix_out_case(const char *test, int use_epoll) {
    int sv[2];
    int sz = RDY_SMALL_BUF;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        out("ready", test, "setup=socketpair_failed|errno=%s", errno_name(errno));
        return;
    }
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sz, sizeof sz);
    setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &sz, sizeof sz);
    out_case(test, sv[0], sv[1], use_epoll);
    close(sv[0]);
    close(sv[1]);
}

/* Buffers are set before bind/connect/accept: the accepted socket inherits
 * the listener's SO_RCVBUF, and the receive window is negotiated during
 * the handshake, so setting it afterwards would leave autotuning free to
 * grow the pair past the fill cap. */
static int tcp_small_pair(int *cli, int *srv) {
    struct sockaddr_in a;
    socklen_t al = sizeof a;
    int sz = RDY_SMALL_BUF;
    int ln = socket(AF_INET, SOCK_STREAM, 0);
    if (ln < 0) return -1;
    setsockopt(ln, SOL_SOCKET, SO_RCVBUF, &sz, sizeof sz);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(ln, (struct sockaddr *)&a, sizeof a) < 0) { close(ln); return -1; }
    if (listen(ln, 1) < 0) { close(ln); return -1; }
    if (getsockname(ln, (struct sockaddr *)&a, &al) < 0) { close(ln); return -1; }
    int c = socket(AF_INET, SOCK_STREAM, 0);
    if (c < 0) { close(ln); return -1; }
    setsockopt(c, SOL_SOCKET, SO_SNDBUF, &sz, sizeof sz);
    setsockopt(c, SOL_SOCKET, SO_RCVBUF, &sz, sizeof sz);
    if (connect(c, (struct sockaddr *)&a, sizeof a) < 0) { close(c); close(ln); return -1; }
    int s = accept(ln, NULL, NULL);
    close(ln);
    if (s < 0) { close(c); return -1; }
    *cli = c; *srv = s;
    return 0;
}

static void tcp_out_case(const char *test) {
    int cli, srv;
    if (tcp_small_pair(&cli, &srv) < 0) {
        out("ready", test, "setup=tcp_pair_failed|errno=%s", errno_name(errno));
        return;
    }
    out_case(test, cli, srv, 0);
    close(cli);
    close(srv);
}

void probe_readiness_out(void) {
    unix_out_case("unix_pollout_backpressure", 0);
    tcp_out_case("tcp_pollout_backpressure");
    unix_out_case("epoll_unix_out_backpressure", 1);
}
