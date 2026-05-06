// /bin/cat — POSIX cat. Reads each path argument (or stdin if
// none) and writes contents to stdout in 4 KiB chunks.

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

static long write_str(long fd, const char *s) {
    long n=0; while (s[n]) n++; return sc3(SYS_write, fd, (long)s, n);
}

static void cat_fd(long fd) {
    char buf[4096];
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
    if (argc < 2) {
        cat_fd(0);
        sc1(SYS_exit, 0);
    }
    long rc = 0;
    for (long i = 1; i < argc; i++) {
        long fd = sc4(SYS_openat, AT_FDCWD, (long)argv[i], O_RDONLY, 0);
        if (fd < 0) {
            write_str(2, "cat: open failed: ");
            write_str(2, argv[i]);
            write_str(2, "\n");
            rc = 1;
            continue;
        }
        cat_fd(fd);
        sc1(SYS_close, fd);
    }
    sc1(SYS_exit, rc);
    __builtin_unreachable();
}
