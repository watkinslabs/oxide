// /bin/sleep — POSIX nanosleep wrapper. Usage: sleep <seconds>.

#include <sys/syscall.h>

struct timespec { long tv_sec; long tv_nsec; };

static long
sc2(long nr, long a0, long a1) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0), "S"(a1) : "rcx","r11","memory"); return r; }
static long
sc1(long nr, long a0) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0) : "rcx","r11","memory"); return r; }

static long parse_int(const char *s) {
    long v = 0; while (*s >= '0' && *s <= '9') { v = v*10 + (*s-'0'); s++; } return v;
}

__attribute__((force_align_arg_pointer))
void _start(void) {
    long argc; char **argv;
    __asm__ volatile ("mov (%%rsp), %0\n\t lea 8(%%rsp), %1\n\t" : "=r"(argc), "=r"(argv));
    long secs = (argc > 1) ? parse_int(argv[1]) : 1;
    struct timespec t = { secs, 0 };
    sc2(SYS_nanosleep, (long)&t, 0);
    sc1(SYS_exit, 0);
    __builtin_unreachable();
}
