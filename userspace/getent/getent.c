// /bin/getent — POSIX getent(1). v1: passwd/group/shadow only.
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

static long read_file_all(const char *path, char *buf, long cap) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    long total = 0;
    while (total < cap) {
        ssize_t n = read(fd, buf + total, cap - total);
        if (n <= 0) break;
        total += n;
    }
    close(fd);
    return total;
}

static int try_match(const char *line, long line_len, const char *target) {
    if (target == 0) {
        write(1, line, line_len);
        write(1, "\n", 1);
        return 1;
    }
    long i = 0, t = 0;
    while (i < line_len && line[i] != ':') {
        if (target[t] != line[i]) return 0;
        i++; t++;
    }
    if (target[t] != 0) return 0;
    write(1, line, line_len);
    write(1, "\n", 1);
    return 1;
}

int main(int argc, char** argv, char** envp) {
    (void)envp;
    if (argc < 2) {
        write(2, "getent: usage: getent <db> [key]\n", 33);
        return 1;
    }
    const char *db = argv[1];
    const char *key = (argc > 2) ? argv[2] : 0;
    const char *path;
    if (strcmp(db, "passwd") == 0)      path = "/etc/passwd";
    else if (strcmp(db, "group") == 0)  path = "/etc/group";
    else if (strcmp(db, "shadow") == 0) path = "/etc/shadow";
    else { write(2, "getent: unknown db\n", 19); return 1; }

    static char buf[16384];
    long n = read_file_all(path, buf, sizeof(buf));
    if (n <= 0) { write(2, "getent: open failed\n", 20); return 1; }

    long start = 0; int matched = 0;
    for (long i = 0; i < n; i++) {
        if (buf[i] == '\n') {
            if (i > start && buf[start] != '#') {
                if (try_match(buf + start, i - start, key)) matched = 1;
            }
            start = i + 1;
        }
    }
    return (key && !matched) ? 2 : 0;
}
