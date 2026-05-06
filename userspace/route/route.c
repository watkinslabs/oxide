// /bin/route — POSIX route(8) reader. Cats /proc/net/route.

#include <sys/syscall.h>

#define O_RDONLY 0
#define AT_FDCWD -100

static long
sc1(long nr, long a0) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0) : "rcx","r11","memory"); return r; }
static long
sc3(long nr, long a0, long a1, long a2) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0), "S"(a1), "d"(a2) : "rcx","r11","memory"); return r; }
static long
sc4(long nr, long a0, long a1, long a2, long a3) {
    long r; register long r10 __asm__("r10") = a3;
    __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0), "S"(a1), "d"(a2), "r"(r10) : "rcx","r11","memory");
    return r;
}

void _start(void) {
    long fd = sc4(SYS_openat, AT_FDCWD, (long)"/proc/net/route", O_RDONLY, 0);
    if (fd < 0) { sc1(SYS_exit, 1); }
    char buf[4096];
    for (;;) {
        long n = sc3(SYS_read, fd, (long)buf, sizeof(buf));
        if (n <= 0) break;
        sc3(SYS_write, 1, (long)buf, n);
    }
    sc1(SYS_close, fd);
    sc1(SYS_exit, 0);
}
