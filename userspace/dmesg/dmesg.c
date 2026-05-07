// /bin/dmesg — read /dev/kmsg and dump to stdout.
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char** argv, char** envp) {
    (void)argc; (void)argv; (void)envp;
    int fd = open("/dev/kmsg", O_RDONLY);
    if (fd < 0) return 1;
    char buf[4096];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0) break;
        write(1, buf, n);
    }
    close(fd);
    return 0;
}
