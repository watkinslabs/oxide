// Tiny TCP echo server. socket → bind → listen → accept → echo
// loop. v1 single connection then exit.

#include <sys/syscall.h>

#define AF_INET     2
#define SOCK_STREAM 1

static long
sc1(long nr, long a0) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0) : "rcx","r11","memory"); return r; }
static long
sc3(long nr, long a0, long a1, long a2) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0), "S"(a1), "d"(a2) : "rcx","r11","memory"); return r; }
static long
sc2(long nr, long a0, long a1) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0), "S"(a1) : "rcx","r11","memory"); return r; }

struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned int   sin_addr;
    unsigned char  sin_zero[8];
};

static long write_str(long fd, const char *s) {
    long n=0; while (s[n]) n++; return sc3(SYS_write, fd, (long)s, n);
}

void
_start(void) {
    long fd = sc3(SYS_socket, AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { write_str(1, "tcp_echo: socket failed\n"); sc1(SYS_exit, 1); }

    struct sockaddr_in a = { 0 };
    a.sin_family = AF_INET;
    a.sin_port   = __builtin_bswap16(8);
    a.sin_addr   = 0;
    if (sc3(SYS_bind, fd, (long)&a, sizeof(a)) < 0) {
        write_str(1, "tcp_echo: bind failed\n"); sc1(SYS_exit, 2);
    }
    if (sc2(SYS_listen, fd, 1) < 0) {
        write_str(1, "tcp_echo: listen failed\n"); sc1(SYS_exit, 3);
    }
    write_str(1, "tcp_echo: listening on 0.0.0.0:8\n");

    long cfd = sc3(SYS_accept, fd, 0, 0);
    if (cfd < 0) { write_str(1, "tcp_echo: accept eagain\n"); sc1(SYS_exit, 4); }

    char buf[256];
    long n = sc3(SYS_read, cfd, (long)buf, sizeof(buf));
    if (n > 0) sc3(SYS_write, cfd, (long)buf, n);
    sc1(SYS_exit, 0);
}
