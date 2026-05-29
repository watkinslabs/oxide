// /bin/socketpair_fork_probe — F245 + F246 probe.
//
// Mimics openssh's atomicio6 pattern: socketpair + fork; the
// reader sets O_NONBLOCK + uses poll(POLLIN, infinite) to wait
// for data. If our cross-process AF_UNIX wake-on-write doesn't
// fire, this hangs (= the openssh privsep bug surfaces here).
//
// 3 round-trips of length-prefixed messages.
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <errno.h>

static void say(const char *s) { int n=0; while(s[n]) n++; write(1, s, n); }

// Like atomicio: write n bytes, retrying on EAGAIN with poll(POLLOUT).
static int xwrite(int fd, const void *p, int n) {
    const char *b = p; int off = 0;
    while (off < n) {
        int w = write(fd, b + off, n - off);
        if (w > 0) { off += w; continue; }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd = { .fd = fd, .events = POLLOUT };
            poll(&pfd, 1, -1);
            continue;
        }
        return -1;
    }
    return 0;
}
// Like atomicio: read n bytes, retrying on EAGAIN with poll(POLLIN).
// This is the exact pattern openssh's atomicio6 uses.
static int xread(int fd, void *p, int n) {
    char *b = p; int off = 0;
    while (off < n) {
        int r = read(fd, b + off, n - off);
        if (r > 0) { off += r; continue; }
        if (r == 0) return -1; // EOF
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            struct pollfd pfd = { .fd = fd, .events = POLLIN };
            poll(&pfd, 1, -1);
            continue;
        }
        return -1;
    }
    return 0;
}

static int send_msg(int fd, const char *body, uint32_t len) {
    if (xwrite(fd, &len, 4) < 0) return -1;
    if (xwrite(fd, body, (int)len) < 0) return -1;
    return 0;
}
static int recv_msg(int fd, char *buf, uint32_t cap, uint32_t *out_len) {
    uint32_t len;
    if (xread(fd, &len, 4) < 0) return -1;
    if (len > cap) return -1;
    if (xread(fd, buf, (int)len) < 0) return -1;
    *out_len = len;
    return 0;
}

int main(void) {
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) < 0) {
        say("probe: socketpair FAIL\n"); return 1;
    }
    // Set BOTH ends nonblocking — atomicio6 only matters when read returns EAGAIN.
    fcntl(sp[0], F_SETFL, O_NONBLOCK);
    fcntl(sp[1], F_SETFL, O_NONBLOCK);
    pid_t pid = fork();
    if (pid < 0) { say("probe: fork FAIL\n"); return 1; }
    if (pid == 0) {
        close(sp[0]);
        char buf[256];
        uint32_t l;
        for (int i = 0; i < 3; i++) {
            if (recv_msg(sp[1], buf, sizeof buf, &l) < 0) {
                say("probe: child recv FAIL\n"); return 1;
            }
            say("probe: child got msg (via poll)\n");
            if (send_msg(sp[1], "ack", 3) < 0) {
                say("probe: child send FAIL\n"); return 1;
            }
        }
        return 0;
    }
    close(sp[1]);
    char buf[256];
    uint32_t l;
    for (int i = 0; i < 3; i++) {
        if (send_msg(sp[0], "ping", 4) < 0) {
            say("probe: parent send FAIL\n"); return 1;
        }
        if (recv_msg(sp[0], buf, sizeof buf, &l) < 0) {
            say("probe: parent recv FAIL\n"); return 1;
        }
        say("probe: parent got reply (via poll)\n");
    }
    waitpid(pid, NULL, 0);
    say("probe: PASS\n");
    return 0;
}
