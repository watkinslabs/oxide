// /bin/ln — POSIX ln(1). Hardlink only (no -s for v1; symlinks
// not supported). Usage: ln <target> <linkpath>

#include <sys/syscall.h>

static long
sc1(long nr, long a0) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0) : "rcx","r11","memory"); return r; }
static long
sc3(long nr, long a0, long a1, long a2) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0), "S"(a1), "d"(a2) : "rcx","r11","memory"); return r; }

static long write_str(long fd, const char *s) {
    long n=0; while (s[n]) n++; return sc3(SYS_write, fd, (long)s, n);
}

__attribute__((force_align_arg_pointer))
void _start(void) {
    long argc; char **argv;
    __asm__ volatile ("mov (%%rsp), %0\n\t lea 8(%%rsp), %1\n\t" : "=r"(argc), "=r"(argv));
    if (argc < 3) { write_str(2, "ln: usage: ln <target> <linkpath>\n"); sc1(SYS_exit, 1); }
    long r;
    __asm__ volatile (
        "mov $86, %%rax\n\t"          // SYS_link
        "mov %1, %%rdi\n\t"
        "mov %2, %%rsi\n\t"
        "syscall"
        : "=a"(r)
        : "r"((long)argv[1]), "r"((long)argv[2])
        : "rdi","rsi","rcx","r11","memory");
    if (r < 0) { write_str(2, "ln: failed\n"); sc1(SYS_exit, 1); }
    sc1(SYS_exit, 0);
}
