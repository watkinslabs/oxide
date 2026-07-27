/* Blocking fd waits: pipe read, AF_UNIX recv, TCP recv — and the one
 * place where a timeout legitimately changes the answer.
 *
 * `sock_intr_errno` (include/net/sock.h:2755-2761) returns -ERESTARTSYS
 * when no SO_{RCV,SND}TIMEO is set and -EINTR when one is, because the
 * residual timeout cannot cross a restart. That makes
 * `unix_recv_timed_sarestart` the discriminating case in this file: same
 * handler, same signal, same data — only the sockopt differs, and Linux
 * flips restart into EINTR. Pipes have no such rule (fs/pipe.c:481 is a
 * bare -ERESTARTSYS), so `pipe_read_sarestart` must resume.
 */
#include "probe.h"

#define PAYLOAD 5

#define FD_SIG_BIT  8
#define FD_DATA_BIT 16

/* Reader runs in a child behind `wait_bounded` for the same reason the
 * lock acquirer does: a missing wake must cost ONE record, not the run. */
static void reader(int rfd, int restart, int is_socket, int timeo_s) {
    char buf[64];
    if (timeo_s > 0) {
        struct timeval tv;
        tv.tv_sec = timeo_s; tv.tv_usec = 0;
        if (setsockopt(rfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) < 0) _exit(CLS_OTHER);
    }
    install_handler(SIGALRM, restart);
    arm_timer_ms(SIG_DELAY_MS);
    ssize_t n = is_socket ? recv(rfd, buf, sizeof buf, 0)
                          : read(rfd, buf, sizeof buf);
    int cls = err_class((int)n, errno);
    disarm_timer();
    _exit(cls | (g_sig_count ? FD_SIG_BIT : 0) | (n == PAYLOAD ? FD_DATA_BIT : 0));
}

static void wait_case(const char *test, int rfd, int wfd,
                      int restart, int is_socket, int timeo_s) {
    pid_t writer = spawn_writer(wfd, RELEASE_MS, PAYLOAD);
    pid_t rd = fork();
    if (rd == 0) reader(rfd, restart, is_socket, timeo_s);
    close(wfd);
    close(rfd);
    int st = 0;
    if (!wait_bounded(rd, BLOCKED_GUARD_MS, &st)) {
        kill(rd, SIGKILL); reap(rd); reap(writer);
        out("fd", test, "outcome=blocked");
        return;
    }
    reap(writer);
    if (!WIFEXITED(st)) { out("fd", test, "outcome=killed"); return; }
    int code = WEXITSTATUS(st);
    out("fd", test, "outcome=%s|sig=%d|payload=%d",
        err_class_name(code & 7), (code & FD_SIG_BIT) ? 1 : 0,
        (code & FD_DATA_BIT) ? 1 : 0);
}

static void pipe_case(const char *test, int restart) {
    int p[2];
    if (pipe(p) < 0) { out("fd", test, "setup=pipe_failed"); return; }
    wait_case(test, p[0], p[1], restart, 0, 0);
}

static void unix_case(const char *test, int restart, int timeo_s) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        out("fd", test, "setup=socketpair_failed|errno=%s", errno_name(errno));
        return;
    }
    wait_case(test, sv[0], sv[1], restart, 1, timeo_s);
}

/* Loopback TCP pair built in-process: `connect` completes immediately
 * against a listening socket, so the blocking wait under test is the
 * `recv`, not the connect. A blocking `connect` cannot be arranged
 * deterministically without an unreachable peer (which then never
 * completes, so the SA_RESTART arm would hang) — see the lane report. */
static int tcp_pair(int *cli, int *srv) {
    struct sockaddr_in a;
    socklen_t al = sizeof a;
    int ln = socket(AF_INET, SOCK_STREAM, 0);
    if (ln < 0) return -1;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(ln, (struct sockaddr *)&a, sizeof a) < 0) { close(ln); return -1; }
    if (listen(ln, 1) < 0) { close(ln); return -1; }
    if (getsockname(ln, (struct sockaddr *)&a, &al) < 0) { close(ln); return -1; }
    int c = socket(AF_INET, SOCK_STREAM, 0);
    if (c < 0) { close(ln); return -1; }
    if (connect(c, (struct sockaddr *)&a, sizeof a) < 0) { close(c); close(ln); return -1; }
    int s = accept(ln, NULL, NULL);
    close(ln);
    if (s < 0) { close(c); return -1; }
    *cli = c; *srv = s;
    return 0;
}

static void tcp_case(const char *test, int restart) {
    int cli, srv;
    if (tcp_pair(&cli, &srv) < 0) {
        out("fd", test, "setup=tcp_pair_failed|errno=%s", errno_name(errno));
        return;
    }
    wait_case(test, cli, srv, restart, 1, 0);
}

void probe_fdwait(void) {
    pipe_case("pipe_read_sarestart", 1);
    pipe_case("pipe_read_norestart", 0);
    unix_case("unix_recv_sarestart", 1, 0);
    unix_case("unix_recv_norestart", 0, 0);
    unix_case("unix_recv_timed_sarestart", 1, 5);
    tcp_case("tcp_recv_sarestart", 1);
    tcp_case("tcp_recv_norestart", 0);
}
