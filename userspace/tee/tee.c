// /bin/tee — POSIX tee(1). Reads stdin, writes to stdout + each path.
// -a appends instead of truncating.
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

int main(int argc, char** argv, char** envp) {
    (void)envp;
    int append = 0;
    int i = 1;
    if (i < argc && strcmp(argv[i], "-a") == 0) { append = 1; i++; }
    int fds[8]; int nfd = 0;
    int flags = O_WRONLY | O_CREAT | (append ? O_APPEND : O_TRUNC);
    while (i < argc && nfd < 8) {
        int fd = open(argv[i], flags, 0644);
        if (fd >= 0) fds[nfd++] = fd;
        i++;
    }
    char buf[4096];
    for (;;) {
        ssize_t n = read(0, buf, sizeof(buf));
        if (n <= 0) break;
        write(1, buf, n);
        for (int j = 0; j < nfd; j++) write(fds[j], buf, n);
    }
    for (int j = 0; j < nfd; j++) close(fds[j]);
    return 0;
}
