// /bin/pwd — print working directory.

#include <sys/syscall.h>

static long
sc1(long nr, long a0) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0) : "rcx","r11","memory"); return r; }
static long
sc2(long nr, long a0, long a1) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0), "S"(a1) : "rcx","r11","memory"); return r; }
static long
sc3(long nr, long a0, long a1, long a2) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0), "S"(a1), "d"(a2) : "rcx","r11","memory"); return r; }

void _start(void) {
    char buf[1024];
    long n = sc2(SYS_getcwd, (long)buf, sizeof(buf) - 1);
    if (n <= 0) { sc1(SYS_exit, 1); }
    if (buf[n-1] == 0) n--;
    sc3(SYS_write, 1, (long)buf, n);
    sc3(SYS_write, 1, (long)"\n", 1);
    sc1(SYS_exit, 0);
}
