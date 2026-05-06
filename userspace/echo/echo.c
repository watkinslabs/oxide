// /bin/echo — POSIX echo. Joins argv[1..] with single spaces,
// writes the result + a trailing newline. -n suppresses newline.

#include <sys/syscall.h>

static long
sc1(long nr, long a0) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0) : "rcx","r11","memory"); return r; }
static long
sc3(long nr, long a0, long a1, long a2) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0), "S"(a1), "d"(a2) : "rcx","r11","memory"); return r; }

static long write_str(long fd, const char *s) {
    long n=0; while (s[n]) n++; return sc3(SYS_write, fd, (long)s, n);
}
static int streq(const char *a, const char *b) {
    while (*a && *b) { if (*a != *b) return 0; a++; b++; }
    return *a == 0 && *b == 0;
}

__attribute__((force_align_arg_pointer))
void _start(void) {
    long argc; char **argv;
    __asm__ volatile ("mov (%%rsp), %0\n\t lea 8(%%rsp), %1\n\t" : "=r"(argc), "=r"(argv));
    int trailing_newline = 1;
    long i = 1;
    if (i < argc && streq(argv[i], "-n")) { trailing_newline = 0; i++; }
    for (; i < argc; i++) {
        write_str(1, argv[i]);
        if (i + 1 < argc) sc3(SYS_write, 1, (long)" ", 1);
    }
    if (trailing_newline) sc3(SYS_write, 1, (long)"\n", 1);
    sc1(SYS_exit, 0);
    __builtin_unreachable();
}
