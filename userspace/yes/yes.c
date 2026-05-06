// /bin/yes — POSIX yes(1). Writes argv[1] (default "y") + newline
// forever until killed.

#include <sys/syscall.h>

static long
sc1(long nr, long a0) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0) : "rcx","r11","memory"); return r; }
static long
sc3(long nr, long a0, long a1, long a2) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0), "S"(a1), "d"(a2) : "rcx","r11","memory"); return r; }

__attribute__((force_align_arg_pointer))
void _start(void) {
    long argc; char **argv;
    __asm__ volatile ("mov (%%rsp), %0\n\t lea 8(%%rsp), %1\n\t" : "=r"(argc), "=r"(argv));
    const char *msg = (argc > 1) ? argv[1] : "y";
    long n = 0; while (msg[n]) n++;
    char buf[128];
    long len = 0;
    while (len + n + 1 < (long)sizeof(buf)) {
        for (long i = 0; i < n; i++) buf[len + i] = msg[i];
        buf[len + n] = '\n';
        len += n + 1;
    }
    for (;;) {
        if (sc3(SYS_write, 1, (long)buf, len) <= 0) break;
    }
    sc1(SYS_exit, 0);
}
