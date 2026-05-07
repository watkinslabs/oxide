// /bin/hostname — read /proc/sys/kernel/hostname and print it.
// Usage: hostname            prints current hostname
//        hostname <name>     sets hostname
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

int main(int argc, char** argv, char** envp) {
    (void)envp;
    if (argc > 1) {
        int fd = open("/proc/sys/kernel/hostname", O_WRONLY | O_TRUNC);
        if (fd < 0) return 1;
        write(fd, argv[1], strlen(argv[1]));
        close(fd);
        return 0;
    }
    int fd = open("/proc/sys/kernel/hostname", O_RDONLY);
    if (fd < 0) return 1;
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n > 0) {
        write(1, buf, n);
        if (buf[n-1] != '\n') write(1, "\n", 1);
    }
    close(fd);
    return 0;
}
