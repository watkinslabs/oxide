// /bin/socketpair_fork_probe — mimics openssh's privsep ssh_msg
// pattern: length-prefixed messages exchanged over AF_UNIX
// socketpair across the privsep boundary.
//
// Steps:
//  1. socketpair + fork
//  2. child: read 4B len, read len bytes, write reply 4B+payload
//  3. parent: write 4B len, write payload, read 4B+payload
//  4. Repeat for 3 round-trips to surface "second-message-lost" bugs.
//
// PASS = parent saw 3 replies; FAIL = any roundtrip stalls.
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdint.h>

static void say(const char *s) { int n=0; while(s[n]) n++; write(1, s, n); }

static int write_all(int fd, const void *p, int n) {
    const char *b = p; int off = 0;
    while (off < n) {
        int w = write(fd, b + off, n - off);
        if (w <= 0) return -1;
        off += w;
    }
    return 0;
}
static int read_all(int fd, void *p, int n) {
    char *b = p; int off = 0;
    while (off < n) {
        int r = read(fd, b + off, n - off);
        if (r <= 0) return -1;
        off += r;
    }
    return 0;
}

static int send_msg(int fd, const char *body, uint32_t len) {
    if (write_all(fd, &len, 4) < 0) return -1;
    if (write_all(fd, body, (int)len) < 0) return -1;
    return 0;
}
static int recv_msg(int fd, char *buf, uint32_t cap, uint32_t *out_len) {
    uint32_t len;
    if (read_all(fd, &len, 4) < 0) return -1;
    if (len > cap) return -1;
    if (read_all(fd, buf, (int)len) < 0) return -1;
    *out_len = len;
    return 0;
}

int main(void) {
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) < 0) {
        say("probe: socketpair FAIL\n"); return 1;
    }
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
            say("probe: child got msg\n");
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
        say("probe: parent got reply\n");
    }
    waitpid(pid, NULL, 0);
    say("probe: PASS\n");
    return 0;
}
