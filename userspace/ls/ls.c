// /bin/ls — minimal POSIX ls. Lists names one per line.
// Usage: ls [path] (default '.')

#include <sys/syscall.h>

#define O_RDONLY    0
#define O_DIRECTORY 0x10000
#define AT_FDCWD    -100

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
    const char *path = (argc > 1) ? argv[1] : ".";
    long fd = sc4(SYS_openat, AT_FDCWD, (long)path, O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) { write_str(2, "ls: open failed\n"); sc1(SYS_exit, 1); }
    char buf[1024];
    for (;;) {
        long n = sc3(SYS_getdents64, fd, (long)buf, sizeof(buf));
        if (n <= 0) break;
        long o = 0;
        while (o < n) {
            unsigned short reclen = *(unsigned short*)(buf + o + 16);
            const char *name = buf + o + 19;
            // Skip "." and ".."
            if (!(name[0]=='.' && (name[1]==0 || (name[1]=='.' && name[2]==0)))) {
                write_str(1, name);
                write_str(1, "\n");
            }
            if (reclen == 0) break;
            o += reclen;
        }
    }
    sc1(SYS_close, fd);
    sc1(SYS_exit, 0);
}
