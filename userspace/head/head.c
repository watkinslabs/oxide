// /bin/head — POSIX head(1). Prints the first N lines (default
// 10) of each path arg (or stdin if none).

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

static long parse_int(const char *s) {
    long v = 0; while (*s >= '0' && *s <= '9') { v = v*10 + (*s-'0'); s++; } return v;
}

static int streq2(const char *a, const char *b) {
    while (*a && *b) { if (*a != *b) return 0; a++; b++; }
    return *a == 0 && *b == 0;
}

static void head_fd(long fd, long n) {
    char buf[4096];
    long emitted = 0;
    while (emitted < n) {
        long got = sc3(SYS_read, fd, (long)buf, sizeof(buf));
        if (got <= 0) break;
        long o = 0;
        while (o < got && emitted < n) {
            long start = o;
            while (o < got && buf[o] != '\n') o++;
            if (o < got) { o++; emitted++; }
            else { sc3(SYS_write, 1, (long)(buf + start), o - start); break; }
            sc3(SYS_write, 1, (long)(buf + start), o - start);
        }
    }
}

__attribute__((force_align_arg_pointer))
void _start(void) {
    long argc; char **argv;
    __asm__ volatile ("mov (%%rsp), %0\n\t lea 8(%%rsp), %1\n\t" : "=r"(argc), "=r"(argv));
    long n = 10;
    long i = 1;
    if (i < argc && streq2(argv[i], "-n") && i+1 < argc) {
        n = parse_int(argv[i+1]);
        i += 2;
    }
    if (i >= argc) { head_fd(0, n); sc1(SYS_exit, 0); }
    for (; i < argc; i++) {
        long fd = sc4(SYS_openat, AT_FDCWD, (long)argv[i], O_RDONLY, 0);
        if (fd < 0) continue;
        head_fd(fd, n);
        sc1(SYS_close, fd);
    }
    sc1(SYS_exit, 0);
}
