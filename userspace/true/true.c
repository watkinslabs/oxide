// /bin/true — exit(0). The simplest POSIX tool.

#include <sys/syscall.h>

static long
sc1(long nr, long a0) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0) : "rcx","r11","memory"); return r; }

void _start(void) { sc1(SYS_exit, 0); __builtin_unreachable(); }
