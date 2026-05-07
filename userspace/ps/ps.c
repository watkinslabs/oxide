// /bin/ps — minimal POSIX ps. Walks /proc, prints pid + comm.
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>

static int is_digits(const char *s) {
    if (!*s) return 0;
    while (*s) { if (*s < '0' || *s > '9') return 0; s++; }
    return 1;
}

static long read_file(const char *path, char *buf, long cap) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, cap);
    close(fd);
    return n;
}

int main(int argc, char** argv, char** envp) {
    (void)argc; (void)argv; (void)envp;
    DIR *d = opendir("/proc");
    if (!d) { write(1, "ps: open /proc failed\n", 22); return 1; }
    write(1, "  PID COMM\n", 11);
    struct dirent *e;
    while ((e = readdir(d)) != 0) {
        if (!is_digits(e->d_name)) continue;
        char path[64];
        int pn = 0;
        memcpy(path + pn, "/proc/", 6); pn += 6;
        long nl = strlen(e->d_name);
        memcpy(path + pn, e->d_name, nl); pn += nl;
        memcpy(path + pn, "/comm", 5); pn += 5;
        path[pn] = 0;
        char cb[64]; long cn = read_file(path, cb, sizeof(cb));
        if (cn < 0) cn = 0;
        while (cn > 0 && (cb[cn-1] == '\n' || cb[cn-1] == 0)) cn--;
        write(1, " ", 1);
        write(1, e->d_name, nl);
        write(1, " ", 1);
        write(1, cb, cn);
        write(1, "\n", 1);
    }
    closedir(d);
    return 0;
}
