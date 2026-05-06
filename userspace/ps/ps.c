// /bin/ps — minimal POSIX ps. Walks /proc, finds numeric tid
// dirs via getdents64, prints "<pid> <comm>" per line.

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

static int is_digits(const char *s) {
    if (!*s) return 0;
    while (*s) { if (*s < '0' || *s > '9') return 0; s++; }
    return 1;
}

static long
read_file(const char *path, char *buf, long cap) {
    long fd = sc4(SYS_openat, AT_FDCWD, (long)path, O_RDONLY, 0);
    if (fd < 0) return -1;
    long n = sc3(SYS_read, fd, (long)buf, cap);
    sc1(SYS_close, fd);
    return n;
}

void
_start(void) {
    long fd = sc4(SYS_openat, AT_FDCWD, (long)"/proc", O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) { write_str(1, "ps: open /proc failed\n"); sc1(SYS_exit, 1); }
    write_str(1, "  PID COMM\n");
    char dbuf[1024];
    for (;;) {
        long n = sc3(SYS_getdents64, fd, (long)dbuf, sizeof(dbuf));
        if (n <= 0) break;
        long o = 0;
        while (o < n) {
            unsigned short reclen = *(unsigned short*)(dbuf + o + 16);
            const char *name = dbuf + o + 19;
            if (is_digits(name)) {
                char path[64];
                long pn = 0;
                const char *p = "/proc/"; while (*p) { path[pn++] = *p++; }
                p = name; while (*p) { path[pn++] = *p++; }
                p = "/comm"; while (*p) { path[pn++] = *p++; }
                path[pn] = 0;
                char cb[64]; long cn = read_file(path, cb, sizeof(cb));
                if (cn < 0) cn = 0;
                while (cn > 0 && (cb[cn-1] == '\n' || cb[cn-1] == 0)) cn--;
                // " <pid> <comm>\n" simple alignment.
                write_str(1, " ");
                write_str(1, name);
                write_str(1, " ");
                sc3(SYS_write, 1, (long)cb, cn);
                write_str(1, "\n");
            }
            if (reclen == 0) break;
            o += reclen;
        }
    }
    sc1(SYS_close, fd);
    sc1(SYS_exit, 0);
}
