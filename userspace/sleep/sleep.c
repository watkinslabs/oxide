// /bin/sleep — POSIX sleep. Usage: sleep <seconds>.
#include "../shared/oxide_start.h"
#include <time.h>

static long parse_int(const char *s) {
    long v = 0; while (*s >= '0' && *s <= '9') { v = v*10 + (*s-'0'); s++; } return v;
}

int main(int argc, char** argv, char** envp) {
    (void)envp;
    long secs = (argc > 1) ? parse_int(argv[1]) : 1;
    struct timespec t = { secs, 0 };
    nanosleep(&t, 0);
    return 0;
}
