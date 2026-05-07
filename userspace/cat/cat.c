// /bin/cat — POSIX cat. Reads each path argument (or stdin if
// none) and writes contents to stdout in 4 KiB chunks.
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

static void cat_fd(int fd) {
    char buf[4096];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0) break;
        write(1, buf, n);
    }
}

int main(int argc, char** argv, char** envp) {
    (void)envp;
    if (argc < 2) {
        cat_fd(0);
        return 0;
    }
    int rc = 0;
    for (int i = 1; i < argc; i++) {
        int fd = open(argv[i], O_RDONLY);
        if (fd < 0) {
            write(2, "cat: open failed: ", 18);
            write(2, argv[i], strlen(argv[i]));
            write(2, "\n", 1);
            rc = 1;
            continue;
        }
        cat_fd(fd);
        close(fd);
    }
    return rc;
}
