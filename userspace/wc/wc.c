// /bin/wc — POSIX wc(1). Counts lines + words + bytes.
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

static void put_dec(int fd, long v) {
    char buf[24]; int n = 0;
    if (v == 0) { buf[n++] = '0'; }
    else { while (v > 0) { buf[n++] = '0' + (v % 10); v /= 10; } }
    char r[24]; for (int i = 0; i < n; i++) r[i] = buf[n-1-i];
    write(fd, r, n);
}

static void wc_fd(int fd, const char *label) {
    long lines = 0, words = 0, bytes = 0;
    int in_word = 0;
    char buf[4096];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0) break;
        bytes += n;
        for (long i = 0; i < n; i++) {
            char c = buf[i];
            if (c == '\n') lines++;
            int sp = (c == ' ' || c == '\t' || c == '\n');
            if (!sp && !in_word) { words++; in_word = 1; }
            else if (sp) { in_word = 0; }
        }
    }
    write(1, " ", 1); put_dec(1, lines);
    write(1, " ", 1); put_dec(1, words);
    write(1, " ", 1); put_dec(1, bytes);
    if (label) { write(1, " ", 1); write(1, label, strlen(label)); }
    write(1, "\n", 1);
}

int main(int argc, char** argv, char** envp) {
    (void)envp;
    if (argc < 2) { wc_fd(0, 0); return 0; }
    for (int i = 1; i < argc; i++) {
        int fd = open(argv[i], O_RDONLY);
        if (fd < 0) continue;
        wc_fd(fd, argv[i]);
        close(fd);
    }
    return 0;
}
