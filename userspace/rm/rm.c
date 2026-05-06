// /bin/rm — POSIX unlink(2). Usage: rm [-r] <path> [...]
// -r: rmdir on directories (single-level; doesn't recurse into
// subdirs yet — v1 limitation).

#include <sys/syscall.h>

#define AT_FDCWD     -100
#define AT_REMOVEDIR  0x200

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
    int recursive = 0;
    long i = 1;
    while (i < argc && argv[i][0] == '-') {
        if (streq(argv[i], "-r") || streq(argv[i], "-R") || streq(argv[i], "-rf")) recursive = 1;
        else break;
        i++;
    }
    if (i >= argc) { write_str(1, "rm: missing operand\n"); sc1(SYS_exit, 1); }
    long rc = 0;
    for (; i < argc; i++) {
        long flags = recursive ? AT_REMOVEDIR : 0;
        // Try plain unlink first; if it fails with EISDIR and -r,
        // retry with AT_REMOVEDIR.
        long r = sc3(SYS_unlinkat, AT_FDCWD, (long)argv[i], 0);
        if (r < 0 && recursive) {
            r = sc3(SYS_unlinkat, AT_FDCWD, (long)argv[i], flags);
        }
        if (r < 0) {
            write_str(1, "rm: failed: ");
            write_str(1, argv[i]);
            write_str(1, "\n");
            rc = 1;
        }
    }
    sc1(SYS_exit, rc);
    __builtin_unreachable();
}
