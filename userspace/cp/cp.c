// /bin/cp — POSIX cp(1). Copies SRC to DST. Single-pair only;
// no -r, no DEST is a directory case yet.

#include <sys/syscall.h>

#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT  00100
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

static long write_str(long fd, const char *s) {
    long n=0; while (s[n]) n++; return sc3(SYS_write, fd, (long)s, n);
}

__attribute__((force_align_arg_pointer))
void _start(void) {
    long argc; char **argv;
    __asm__ volatile ("mov (%%rsp), %0\n\t lea 8(%%rsp), %1\n\t" : "=r"(argc), "=r"(argv));
    if (argc < 3) { write_str(2, "cp: usage: cp SRC DST\n"); sc1(SYS_exit, 1); }
    long src = sc4(SYS_openat, AT_FDCWD, (long)argv[1], O_RDONLY, 0);
    if (src < 0) { write_str(2, "cp: open src failed\n"); sc1(SYS_exit, 1); }
    long dst = sc4(SYS_openat, AT_FDCWD, (long)argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dst < 0) { write_str(2, "cp: open dst failed\n"); sc1(SYS_close, src); sc1(SYS_exit, 1); }
    char buf[4096];
    for (;;) {
        long n = sc3(SYS_read, src, (long)buf, sizeof(buf));
        if (n <= 0) break;
        long off = 0;
        while (off < n) {
            long w = sc3(SYS_write, dst, (long)(buf + off), n - off);
            if (w <= 0) { write_str(2, "cp: write failed\n"); sc1(SYS_exit, 1); }
            off += w;
        }
    }
    sc1(SYS_close, src);
    sc1(SYS_close, dst);
    sc1(SYS_exit, 0);
}
