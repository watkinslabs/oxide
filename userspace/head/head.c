// /bin/head — POSIX head(1). Prints the first N lines (default 10).
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

static long parse_int(const char *s) {
    long v = 0; while (*s >= '0' && *s <= '9') { v = v*10 + (*s-'0'); s++; } return v;
}

static void head_fd(int fd, long n) {
    char buf[4096];
    long emitted = 0;
    while (emitted < n) {
        ssize_t got = read(fd, buf, sizeof(buf));
        if (got <= 0) break;
        long o = 0;
        while (o < got && emitted < n) {
            long start = o;
            while (o < got && buf[o] != '\n') o++;
            if (o < got) { o++; emitted++; }
            else { write(1, buf + start, o - start); break; }
            write(1, buf + start, o - start);
        }
    }
}

int main(int argc, char** argv, char** envp) {
    (void)envp;
    long n = 10;
    int i = 1;
    if (i < argc && strcmp(argv[i], "-n") == 0 && i+1 < argc) {
        n = parse_int(argv[i+1]);
        i += 2;
    }
    if (i >= argc) { head_fd(0, n); return 0; }
    for (; i < argc; i++) {
        int fd = open(argv[i], O_RDONLY);
        if (fd < 0) continue;
        head_fd(fd, n);
        close(fd);
    }
    return 0;
}
