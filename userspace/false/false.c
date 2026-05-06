// /bin/false — exit(1).

#include <sys/syscall.h>

static long
sc1(long nr, long a0) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0) : "rcx","r11","memory"); return r; }

void _start(void) { sc1(SYS_exit, 1); __builtin_unreachable(); }
