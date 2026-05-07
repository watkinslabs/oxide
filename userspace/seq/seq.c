// /bin/seq — POSIX seq(1). Usage:
//   seq <last>            1..last inclusive
//   seq <first> <last>    first..last
//   seq <first> <step> <last>
#include "../shared/oxide_start.h"
#include <unistd.h>

static long parse_long(const char *s) {
    long v = 0; int neg = 0;
    if (*s == '-') { neg = 1; s++; }
    while (*s >= '0' && *s <= '9') { v = v * 10 + (*s - '0'); s++; }
    return neg ? -v : v;
}

static void put_long(long v) {
    char buf[24]; int n = 0; int neg = 0;
    if (v < 0) { neg = 1; v = -v; }
    if (v == 0) { buf[n++] = '0'; }
    else { while (v > 0) { buf[n++] = '0' + (v % 10); v /= 10; } }
    if (neg) { buf[n++] = '-'; }
    char r[24]; for (int i = 0; i < n; i++) r[i] = buf[n-1-i];
    r[n++] = '\n';
    write(1, r, n);
}

int main(int argc, char** argv, char** envp) {
    (void)envp;
    long first = 1, step = 1, last = 0;
    if (argc == 2) last = parse_long(argv[1]);
    else if (argc == 3) { first = parse_long(argv[1]); last = parse_long(argv[2]); }
    else if (argc == 4) { first = parse_long(argv[1]); step = parse_long(argv[2]); last = parse_long(argv[3]); }
    else return 1;
    if (step > 0) {
        for (long v = first; v <= last; v += step) put_long(v);
    } else if (step < 0) {
        for (long v = first; v >= last; v += step) put_long(v);
    }
    return 0;
}
