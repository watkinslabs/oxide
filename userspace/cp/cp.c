// /bin/cp — POSIX cp(1). Copies SRC to DST. Single-pair only.
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char** argv, char** envp) {
    (void)envp;
    if (argc < 3) { write(2, "cp: usage: cp SRC DST\n", 22); return 1; }
    int src = open(argv[1], O_RDONLY);
    if (src < 0) { write(2, "cp: open src failed\n", 20); return 1; }
    int dst = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dst < 0) { write(2, "cp: open dst failed\n", 20); close(src); return 1; }
    char buf[4096];
    for (;;) {
        ssize_t n = read(src, buf, sizeof(buf));
        if (n <= 0) break;
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(dst, buf + off, n - off);
            if (w <= 0) { write(2, "cp: write failed\n", 17); return 1; }
            off += w;
        }
    }
    close(src);
    close(dst);
    return 0;
}
