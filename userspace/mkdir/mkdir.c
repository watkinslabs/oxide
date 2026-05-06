// /bin/mkdir — POSIX mkdir(2). Usage: mkdir <path> [...]

#include <sys/syscall.h>

static long
sc1(long nr, long a0) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0) : "rcx","r11","memory"); return r; }
static long
sc2(long nr, long a0, long a1) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0), "S"(a1) : "rcx","r11","memory"); return r; }
static long
sc3(long nr, long a0, long a1, long a2) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0), "S"(a1), "d"(a2) : "rcx","r11","memory"); return r; }

static long write_str(long fd, const char *s) {
    long n=0; while (s[n]) n++; return sc3(SYS_write, fd, (long)s, n);
}

__attribute__((force_align_arg_pointer))
void _start(void) {
    long argc; char **argv;
    __asm__ volatile ("mov (%%rsp), %0\n\t lea 8(%%rsp), %1\n\t" : "=r"(argc), "=r"(argv));
    if (argc < 2) { write_str(1, "mkdir: missing operand\n"); sc1(SYS_exit, 1); }
    long rc = 0;
    for (long i = 1; i < argc; i++) {
        if (sc2(SYS_mkdir, (long)argv[i], 0755) < 0) {
            write_str(1, "mkdir: failed: ");
            write_str(1, argv[i]);
            write_str(1, "\n");
            rc = 1;
        }
    }
    sc1(SYS_exit, rc);
    __builtin_unreachable();
}
