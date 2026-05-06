// /bin/nproc — print CPU count. Reads /sys/devices/system/cpu/online
// and emits the count of CPUs in the range list.

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

static long parse_int_at(const char *s, long *cur) {
    long v = 0;
    while (s[*cur] >= '0' && s[*cur] <= '9') { v = v * 10 + (s[*cur] - '0'); (*cur)++; }
    return v;
}

void _start(void) {
    char buf[256];
    long fd = sc4(SYS_openat, AT_FDCWD, (long)"/sys/devices/system/cpu/online", O_RDONLY, 0);
    if (fd < 0) {
        sc3(SYS_write, 1, (long)"1\n", 2);
        sc1(SYS_exit, 0);
    }
    long n = sc3(SYS_read, fd, (long)buf, sizeof(buf) - 1);
    sc1(SYS_close, fd);
    if (n <= 0) {
        sc3(SYS_write, 1, (long)"1\n", 2);
        sc1(SYS_exit, 0);
    }
    buf[n] = 0;
    // Parse "a-b,c-d,e" — sum (b-a+1) for each range.
    long total = 0;
    long i = 0;
    while (i < n && buf[i] != '\n') {
        long a = parse_int_at(buf, &i);
        long b = a;
        if (buf[i] == '-') { i++; b = parse_int_at(buf, &i); }
        total += (b - a + 1);
        if (buf[i] == ',') i++;
    }
    if (total <= 0) total = 1;
    char out[16]; int o = 0;
    if (total == 0) out[o++] = '0';
    long t = total;
    char tmp[16]; int tn = 0;
    while (t > 0) { tmp[tn++] = '0' + (t % 10); t /= 10; }
    for (int k = 0; k < tn; k++) out[o++] = tmp[tn - 1 - k];
    out[o++] = '\n';
    sc3(SYS_write, 1, (long)out, o);
    sc1(SYS_exit, 0);
}
