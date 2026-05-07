// /bin/nproc — print CPU count. Reads /sys/devices/system/cpu/online
// and emits the count of CPUs in the range list.
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <fcntl.h>

static long parse_int_at(const char *s, long *cur) {
    long v = 0;
    while (s[*cur] >= '0' && s[*cur] <= '9') { v = v * 10 + (s[*cur] - '0'); (*cur)++; }
    return v;
}

int main(int argc, char** argv, char** envp) {
    (void)argc; (void)argv; (void)envp;
    char buf[256];
    int fd = open("/sys/devices/system/cpu/online", O_RDONLY);
    if (fd < 0) { write(1, "1\n", 2); return 0; }
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) { write(1, "1\n", 2); return 0; }
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
    long t = total;
    char tmp[16]; int tn = 0;
    while (t > 0) { tmp[tn++] = '0' + (t % 10); t /= 10; }
    for (int k = 0; k < tn; k++) out[o++] = tmp[tn - 1 - k];
    out[o++] = '\n';
    write(1, out, o);
    return 0;
}
