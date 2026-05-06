// /bin/nc — minimal netcat. Two modes:
//   nc <host> <port>          TCP client; pipes stdin to socket + socket to stdout
//   nc -l <port>              TCP listener; accepts one conn, same pipe
// Loops byte-by-byte (single-threaded, no epoll). Exits on any
// EOF.

#include <sys/syscall.h>

#define AF_INET     2
#define SOCK_STREAM 1

static long
sc1(long nr, long a0) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0) : "rcx","r11","memory"); return r; }
static long
sc2(long nr, long a0, long a1) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0), "S"(a1) : "rcx","r11","memory"); return r; }
static long
sc3(long nr, long a0, long a1, long a2) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0), "S"(a1), "d"(a2) : "rcx","r11","memory"); return r; }

struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned int   sin_addr;
    unsigned char  sin_zero[8];
};

static long write_str(long fd, const char *s) {
    long n=0; while (s[n]) n++; return sc3(SYS_write, fd, (long)s, n);
}
static int streq(const char *a, const char *b) {
    while (*a && *b) { if (*a != *b) return 0; a++; b++; }
    return *a == 0 && *b == 0;
}
static long parse_int(const char *s) {
    long v = 0; while (*s >= '0' && *s <= '9') { v = v*10 + (*s-'0'); s++; } return v;
}
// Tiny IPv4 parser: 127.0.0.1 → 0x0100007f host order? Linux uses
// network order in sin_addr. Build 0xAABBCCDD for "A.B.C.D" then
// htonl.
static unsigned int parse_ip(const char *s) {
    unsigned int a[4] = {0}; int idx = 0;
    while (*s && idx < 4) {
        unsigned int v = 0;
        while (*s >= '0' && *s <= '9') { v = v*10 + (*s - '0'); s++; }
        a[idx++] = v;
        if (*s == '.') s++;
    }
    return (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
}

static void pipe_loop(long fd) {
    char buf[256];
    for (;;) {
        long n = sc3(SYS_read, fd, (long)buf, sizeof(buf));
        if (n <= 0) break;
        sc3(SYS_write, 1, (long)buf, n);
    }
}

__attribute__((force_align_arg_pointer))
void _start(void) {
    long argc; char **argv;
    __asm__ volatile ("mov (%%rsp), %0\n\t lea 8(%%rsp), %1\n\t" : "=r"(argc), "=r"(argv));
    if (argc < 3) { write_str(2, "nc: usage: nc <host> <port> | nc -l <port>\n"); sc1(SYS_exit, 1); }
    int listen_mode = streq(argv[1], "-l");
    long fd = sc3(SYS_socket, AF_INET, SOCK_STREAM, 0);
    if (fd < 0) sc1(SYS_exit, 1);

    if (listen_mode) {
        long port = parse_int(argv[2]);
        struct sockaddr_in a = { AF_INET, __builtin_bswap16((unsigned short)port), 0, {0} };
        if (sc3(SYS_bind, fd, (long)&a, sizeof(a)) < 0) sc1(SYS_exit, 2);
        if (sc2(SYS_listen, fd, 1) < 0) sc1(SYS_exit, 3);
        long cfd = sc3(SYS_accept, fd, 0, 0);
        if (cfd < 0) sc1(SYS_exit, 4);
        pipe_loop(cfd);
        sc1(SYS_close, cfd);
    } else {
        long port = parse_int(argv[2]);
        unsigned int ip_host = parse_ip(argv[1]);
        struct sockaddr_in a = { AF_INET, __builtin_bswap16((unsigned short)port),
                                  __builtin_bswap32(ip_host), {0} };
        if (sc3(SYS_connect, fd, (long)&a, sizeof(a)) < 0) {
            write_str(2, "nc: connect failed\n"); sc1(SYS_exit, 5);
        }
        pipe_loop(fd);
    }
    sc1(SYS_close, fd);
    sc1(SYS_exit, 0);
}
