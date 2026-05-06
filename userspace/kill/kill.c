// /bin/kill — minimal POSIX signal sender. Usage:
//   kill <pid>            sends SIGTERM
//   kill -<sig> <pid>     sends signal number <sig>
// Built static-pie -nostartfiles, so we walk argc/argv off the
// initial stack frame ourselves: rsp points to argc, argv lives
// at rsp+8.

#include <sys/syscall.h>

#define SIGTERM 15

static long
sc1(long nr, long a0) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0) : "rcx","r11","memory"); return r; }
static long
sc2(long nr, long a0, long a1) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0), "S"(a1) : "rcx","r11","memory"); return r; }
static long
sc3(long nr, long a0, long a1, long a2) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0), "S"(a1), "d"(a2) : "rcx","r11","memory"); return r; }

static long write_str(long fd, const char *s) {
    long n = 0; while (s[n]) n++;
    return sc3(SYS_write, fd, (long)s, n);
}

static long parse_int(const char *s) {
    long v = 0;
    while (*s >= '0' && *s <= '9') { v = v * 10 + (*s - '0'); s++; }
    return v;
}

__attribute__((force_align_arg_pointer))
void _start(void) {
    long argc;
    char **argv;
    __asm__ volatile (
        "mov (%%rsp), %0\n\t"
        "lea 8(%%rsp), %1\n\t"
        : "=r"(argc), "=r"(argv)
    );
    long sig = SIGTERM;
    long idx = 1;
    if (argc > 1 && argv[1][0] == '-' && argv[1][1] >= '0' && argv[1][1] <= '9') {
        sig = parse_int(argv[1] + 1);
        idx++;
    }
    if (idx >= argc) {
        write_str(1, "kill: missing pid\n");
        sc1(SYS_exit, 1);
    }
    long pid = parse_int(argv[idx]);
    long r = sc2(SYS_kill, pid, sig);
    if (r < 0) {
        write_str(1, "kill: failed\n");
        sc1(SYS_exit, 1);
    }
    sc1(SYS_exit, 0);
    __builtin_unreachable();
}
