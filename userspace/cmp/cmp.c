// /bin/cmp — POSIX cmp(1). Reads two files; exit 0 if identical,
// 1 if different, 2 on I/O error.

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

__attribute__((force_align_arg_pointer))
void _start(void) {
    long argc; char **argv;
    __asm__ volatile ("mov (%%rsp), %0\n\t lea 8(%%rsp), %1\n\t" : "=r"(argc), "=r"(argv));
    if (argc < 3) { write_str(2, "cmp: usage: cmp <a> <b>\n"); sc1(SYS_exit, 2); }
    long a = sc4(SYS_openat, AT_FDCWD, (long)argv[1], O_RDONLY, 0);
    long b = sc4(SYS_openat, AT_FDCWD, (long)argv[2], O_RDONLY, 0);
    if (a < 0 || b < 0) { write_str(2, "cmp: open failed\n"); sc1(SYS_exit, 2); }
    char ba[4096], bb[4096];
    for (;;) {
        long na = sc3(SYS_read, a, (long)ba, sizeof(ba));
        long nb = sc3(SYS_read, b, (long)bb, sizeof(bb));
        if (na < 0 || nb < 0) { sc1(SYS_exit, 2); }
        if (na != nb) { sc1(SYS_exit, 1); }
        if (na == 0) { sc1(SYS_exit, 0); }
        for (long i = 0; i < na; i++) {
            if (ba[i] != bb[i]) { write_str(1, "cmp: differ\n"); sc1(SYS_exit, 1); }
        }
    }
}
