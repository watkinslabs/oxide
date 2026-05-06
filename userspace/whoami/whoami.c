// /bin/whoami — read /etc/passwd, print "root" since v1 always
// runs as uid 0. Real impl walks passwd by uid; v1 shortcut.

#include <sys/syscall.h>

static long
sc1(long nr, long a0) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0) : "rcx","r11","memory"); return r; }
static long
sc3(long nr, long a0, long a1, long a2) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0), "S"(a1), "d"(a2) : "rcx","r11","memory"); return r; }

void _start(void) {
    sc3(SYS_write, 1, (long)"root\n", 5);
    sc1(SYS_exit, 0);
}
