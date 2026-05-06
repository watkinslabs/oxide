// /bin/df — disk-free. v1: statfs every path arg (or "/" if
// none), prints "<dev> <size> <used> <avail> <pct%> <mount>"
// using the f_blocks/f_bavail fields.

#include <sys/syscall.h>

#define AT_FDCWD -100

struct statfs {
    long f_type;
    long f_bsize;
    unsigned long f_blocks;
    unsigned long f_bfree;
    unsigned long f_bavail;
    unsigned long f_files;
    unsigned long f_ffree;
    long f_fsid[2];
    long f_namelen;
    long f_frsize;
    long f_flags;
    long f_spare[4];
};

static long
sc1(long nr, long a0) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0) : "rcx","r11","memory"); return r; }
static long
sc2(long nr, long a0, long a1) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0), "S"(a1) : "rcx","r11","memory"); return r; }
static long
sc3(long nr, long a0, long a1, long a2) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0), "S"(a1), "d"(a2) : "rcx","r11","memory"); return r; }

static void put_dec(unsigned long v) {
    char buf[24]; int n = 0;
    if (v == 0) { buf[n++] = '0'; }
    else { while (v > 0) { buf[n++] = '0' + (v % 10); v /= 10; } }
    char r[24]; for (int i = 0; i < n; i++) r[i] = buf[n-1-i];
    sc3(SYS_write, 1, (long)r, n);
}
static long write_str(long fd, const char *s) {
    long n=0; while (s[n]) n++; return sc3(SYS_write, fd, (long)s, n);
}

__attribute__((force_align_arg_pointer))
void _start(void) {
    long argc; char **argv;
    __asm__ volatile ("mov (%%rsp), %0\n\t lea 8(%%rsp), %1\n\t" : "=r"(argc), "=r"(argv));
    write_str(1, "Filesystem    1K-blocks   Used    Available  Mounted-on\n");
    long start = (argc > 1) ? 1 : 0;
    long end = (argc > 1) ? argc : 1;
    const char *def = "/";
    for (long i = start; i < end; i++) {
        const char *path = (argc > 1) ? argv[i] : def;
        struct statfs s = { 0 };
        if (sc2(SYS_statfs, (long)path, (long)&s) < 0) continue;
        write_str(1, "ext4         ");
        put_dec(s.f_blocks);  write_str(1, "    ");
        put_dec(s.f_blocks - s.f_bavail); write_str(1, "    ");
        put_dec(s.f_bavail);  write_str(1, "    ");
        write_str(1, path);
        write_str(1, "\n");
    }
    sc1(SYS_exit, 0);
}
