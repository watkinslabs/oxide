// /bin/wc — POSIX wc(1). Counts lines + words + bytes for each
// path arg (or stdin if none).

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

static void put_dec(long fd, long v) {
    char buf[24]; int n = 0;
    if (v == 0) { buf[n++] = '0'; }
    else { while (v > 0) { buf[n++] = '0' + (v % 10); v /= 10; } }
    char r[24]; for (int i = 0; i < n; i++) r[i] = buf[n-1-i];
    sc3(SYS_write, fd, (long)r, n);
}

static void wc_fd(long fd, const char *label) {
    long lines = 0, words = 0, bytes = 0;
    int in_word = 0;
    char buf[4096];
    for (;;) {
        long n = sc3(SYS_read, fd, (long)buf, sizeof(buf));
        if (n <= 0) break;
        bytes += n;
        for (long i = 0; i < n; i++) {
            char c = buf[i];
            if (c == '\n') lines++;
            int sp = (c == ' ' || c == '\t' || c == '\n');
            if (!sp && !in_word) { words++; in_word = 1; }
            else if (sp) { in_word = 0; }
        }
    }
    sc3(SYS_write, 1, (long)" ", 1);
    put_dec(1, lines);
    sc3(SYS_write, 1, (long)" ", 1);
    put_dec(1, words);
    sc3(SYS_write, 1, (long)" ", 1);
    put_dec(1, bytes);
    if (label) {
        sc3(SYS_write, 1, (long)" ", 1);
        long n = 0; while (label[n]) n++;
        sc3(SYS_write, 1, (long)label, n);
    }
    sc3(SYS_write, 1, (long)"\n", 1);
}

__attribute__((force_align_arg_pointer))
void _start(void) {
    long argc; char **argv;
    __asm__ volatile ("mov (%%rsp), %0\n\t lea 8(%%rsp), %1\n\t" : "=r"(argc), "=r"(argv));
    if (argc < 2) {
        wc_fd(0, 0);
        sc1(SYS_exit, 0);
    }
    for (long i = 1; i < argc; i++) {
        long fd = sc4(SYS_openat, AT_FDCWD, (long)argv[i], O_RDONLY, 0);
        if (fd < 0) continue;
        wc_fd(fd, argv[i]);
        sc1(SYS_close, fd);
    }
    sc1(SYS_exit, 0);
}
