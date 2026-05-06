// /bin/tee — POSIX tee(1). Reads stdin, writes to stdout AND to
// each path arg. -a appends instead of truncating.

#include <sys/syscall.h>

#define O_WRONLY 1
#define O_CREAT  00100
#define O_TRUNC  01000
#define O_APPEND 02000
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

static int streq(const char *a, const char *b) {
    while (*a && *b) { if (*a != *b) return 0; a++; b++; }
    return *a == 0 && *b == 0;
}

__attribute__((force_align_arg_pointer))
void _start(void) {
    long argc; char **argv;
    __asm__ volatile ("mov (%%rsp), %0\n\t lea 8(%%rsp), %1\n\t" : "=r"(argc), "=r"(argv));
    int append = 0;
    long i = 1;
    if (i < argc && streq(argv[i], "-a")) { append = 1; i++; }
    long fds[8]; int nfd = 0;
    long flags = O_WRONLY | O_CREAT | (append ? O_APPEND : O_TRUNC);
    while (i < argc && nfd < 8) {
        long fd = sc4(SYS_openat, AT_FDCWD, (long)argv[i], flags, 0644);
        if (fd >= 0) fds[nfd++] = fd;
        i++;
    }
    char buf[4096];
    for (;;) {
        long n = sc3(SYS_read, 0, (long)buf, sizeof(buf));
        if (n <= 0) break;
        sc3(SYS_write, 1, (long)buf, n);
        for (int j = 0; j < nfd; j++) sc3(SYS_write, fds[j], (long)buf, n);
    }
    for (int j = 0; j < nfd; j++) sc1(SYS_close, fds[j]);
    sc1(SYS_exit, 0);
}
