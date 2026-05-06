// /bin/hostname — read /proc/sys/kernel/hostname and print it.
// Usage: hostname           prints current hostname
//        hostname <name>    sets hostname (write to procfs slot)

#include <sys/syscall.h>

#define O_RDONLY 0
#define O_WRONLY 1
#define O_TRUNC  01000
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

__attribute__((force_align_arg_pointer))
void _start(void) {
    long argc; char **argv;
    __asm__ volatile ("mov (%%rsp), %0\n\t lea 8(%%rsp), %1\n\t" : "=r"(argc), "=r"(argv));
    if (argc > 1) {
        long fd = sc4(SYS_openat, AT_FDCWD, (long)"/proc/sys/kernel/hostname", O_WRONLY | O_TRUNC, 0);
        if (fd < 0) { sc1(SYS_exit, 1); }
        long n = 0; while (argv[1][n]) n++;
        sc3(SYS_write, fd, (long)argv[1], n);
        sc1(SYS_close, fd);
        sc1(SYS_exit, 0);
    }
    long fd = sc4(SYS_openat, AT_FDCWD, (long)"/proc/sys/kernel/hostname", O_RDONLY, 0);
    if (fd < 0) { sc1(SYS_exit, 1); }
    char buf[256];
    long n = sc3(SYS_read, fd, (long)buf, sizeof(buf));
    if (n > 0) {
        sc3(SYS_write, 1, (long)buf, n);
        if (buf[n-1] != '\n') sc3(SYS_write, 1, (long)"\n", 1);
    }
    sc1(SYS_close, fd);
    sc1(SYS_exit, 0);
    __builtin_unreachable();
}
