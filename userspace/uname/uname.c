// /bin/uname — print system info via SYS_uname.

#include <sys/syscall.h>

#define UTSBUF 6 * 65

static long
sc1(long nr, long a0) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0) : "rcx","r11","memory"); return r; }
static long
sc3(long nr, long a0, long a1, long a2) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0), "S"(a1), "d"(a2) : "rcx","r11","memory"); return r; }

static int streq(const char *a, const char *b) {
    while (*a && *b) { if (*a != *b) return 0; a++; b++; }
    return *a == 0 && *b == 0;
}

static long write_field(const char *p) {
    long n = 0; while (p[n] && p[n] != ' ' && p[n] != '\n') n++;
    return sc3(SYS_write, 1, (long)p, n);
}

__attribute__((force_align_arg_pointer))
void _start(void) {
    long argc; char **argv;
    __asm__ volatile ("mov (%%rsp), %0\n\t lea 8(%%rsp), %1\n\t" : "=r"(argc), "=r"(argv));
    char buf[UTSBUF]; for (int i = 0; i < UTSBUF; i++) buf[i] = 0;
    if (sc1(SYS_uname, (long)buf) < 0) sc1(SYS_exit, 1);
    // Layout: sysname[65], nodename[65], release[65], version[65],
    //         machine[65], domainname[65].
    // -a prints all; default just -s (sysname).
    int all = 0;
    for (long i = 1; i < argc; i++) if (streq(argv[i], "-a")) all = 1;
    write_field(buf);                  // sysname
    if (all) {
        sc3(SYS_write, 1, (long)" ", 1); write_field(buf + 65);
        sc3(SYS_write, 1, (long)" ", 1); write_field(buf + 65*2);
        sc3(SYS_write, 1, (long)" ", 1); write_field(buf + 65*3);
        sc3(SYS_write, 1, (long)" ", 1); write_field(buf + 65*4);
    }
    sc3(SYS_write, 1, (long)"\n", 1);
    sc1(SYS_exit, 0);
}
