// /bin/tcp_smoke — TCP outbound connect validation after DHCP.
// Connects to slirp's gateway-mapped host services (10.0.2.2:22 →
// host SSH if present, 10.0.2.3:53 → DNS via TCP if slirp forwards).
// Any successful read or a fast clean errno (ECONNREFUSED) counts
// as TCP-state-machine-works. Pure timeout is the only failure.

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <fcntl.h>

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef SOCK_STREAM
#define SOCK_STREAM 1
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK 0x800
#endif

struct sa_in {
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned int   sin_addr;
    unsigned char  zero[8];
};

static unsigned short htons16(unsigned short v) {
    return ((v & 0xff) << 8) | ((v >> 8) & 0xff);
}

// Encode dotted-quad a.b.c.d into NET BE u32 stored as host LE bytes.
static unsigned int ip4(unsigned a, unsigned b, unsigned c, unsigned d) {
    return a | (b << 8) | (c << 16) | (d << 24);
}

static int try_connect(unsigned int dst_be, unsigned short port,
                       const char* label)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        char b[80]; int n = snprintf(b, sizeof(b),
            "tcp_smoke: %s socket errno=%d\n", label, errno);
        write(1, b, n);
        return -1;
    }
    struct sa_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port   = htons16(port);
    dst.sin_addr   = dst_be;
    int rc = connect(fd, (struct sockaddr*)&dst, sizeof(dst));
    if (rc == 0) {
        char b[96]; int n = snprintf(b, sizeof(b),
            "tcp_smoke: %s connect OK\n", label);
        write(1, b, n);
        // Read a few bytes if available (e.g. SSH banner).
        unsigned char buf[64];
        // Non-blocking read attempt — just enough to confirm rx works.
        for (int i = 0; i < 50; i++) {
            ssize_t r = read(fd, buf, sizeof(buf));
            if (r > 0) {
                char out[160];
                int outn = snprintf(out, sizeof(out),
                    "tcp_smoke: %s rx=%d first='%.*s'\n",
                    label, (int)r, (int)(r > 24 ? 24 : r), buf);
                write(1, out, outn);
                close(fd);
                return 0;
            }
            if (r == 0) break;  // EOF
            usleep(20000);
        }
        close(fd);
        return 0;
    }
    char b[96]; int n = snprintf(b, sizeof(b),
        "tcp_smoke: %s connect errno=%d\n", label, errno);
    write(1, b, n);
    close(fd);
    return rc;
}

int main(int argc, char** argv, char** envp) {
    (void)argc; (void)argv; (void)envp;
    int hits = 0;
    // 10.0.2.2:22 — slirp routes to host's localhost:22 (sshd typical).
    if (try_connect(ip4(10, 0, 2, 2), 22, "10.0.2.2:22") == 0) hits++;
    // 10.0.2.3:53 — slirp DNS proxy (TCP fallback).
    if (try_connect(ip4(10, 0, 2, 3), 53, "10.0.2.3:53") == 0) hits++;
    if (hits > 0) {
        char out[64]; int n = snprintf(out, sizeof(out),
            "tcp_smoke: PASS hits=%d\n", hits);
        write(1, out, n);
        return 0;
    }
    write(1, "tcp_smoke: no reachable target (TCP state-machine still ran)\n", 62);
    return 1;
}
