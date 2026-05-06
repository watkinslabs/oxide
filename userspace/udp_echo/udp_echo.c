// Tiny UDP echo server. Binds 0.0.0.0:7  ; for each datagram, sends the
// same payload back to the source. Exits after N datagrams (default 4).
// Used to prove the in-kernel net stack from real-musl userspace.

#include <sys/syscall.h>

#define AF_INET     2
#define SOCK_DGRAM  2

static long
sc1(long nr, long a0) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0) : "rcx","r11","memory"); return r; }
static long
sc3(long nr, long a0, long a1, long a2) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0), "S"(a1), "d"(a2) : "rcx","r11","memory"); return r; }
static long
sc6(long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
    long r;
    register long r10 __asm__("r10") = a3;
    register long r8  __asm__("r8")  = a4;
    register long r9  __asm__("r9")  = a5;
    __asm__ volatile ("syscall"
        : "=a"(r)
        : "0"(nr), "D"(a0), "S"(a1), "d"(a2), "r"(r10), "r"(r8), "r"(r9)
        : "rcx","r11","memory");
    return r;
}

struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned int   sin_addr;
    unsigned char  sin_zero[8];
};

static long
write_str(long fd, const char *s) {
    long n = 0; while (s[n]) n++;
    return sc3(SYS_write, fd, (long)s, n);
}

void
_start(void) {
    long fd = sc3(SYS_socket, AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { write_str(1, "udp_echo: socket failed\n"); sc1(SYS_exit, 1); }

    struct sockaddr_in a = { 0 };
    a.sin_family = AF_INET;
    a.sin_port   = __builtin_bswap16(7);
    a.sin_addr   = 0;  // 0.0.0.0
    if (sc3(SYS_bind, fd, (long)&a, sizeof(a)) < 0) {
        write_str(1, "udp_echo: bind failed\n");
        sc1(SYS_exit, 2);
    }
    write_str(1, "udp_echo: bound 0.0.0.0:7, looping\n");

    char buf[256];
    for (int i = 0; i < 4; i++) {
        struct sockaddr_in src = { 0 };
        unsigned int slen = sizeof(src);
        long n = sc6(SYS_recvfrom, fd, (long)buf, sizeof(buf), 0, (long)&src, (long)&slen);
        if (n <= 0) break;
        sc6(SYS_sendto, fd, (long)buf, n, 0, (long)&src, sizeof(src));
    }
    sc1(SYS_exit, 0);
}
