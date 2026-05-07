// /bin/df — disk-free via statfs(2).
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <sys/vfs.h>
#include <string.h>

static void put_dec(unsigned long v) {
    char buf[24]; int n = 0;
    if (v == 0) { buf[n++] = '0'; }
    else { while (v > 0) { buf[n++] = '0' + (v % 10); v /= 10; } }
    char r[24]; for (int i = 0; i < n; i++) r[i] = buf[n-1-i];
    write(1, r, n);
}

int main(int argc, char** argv, char** envp) {
    (void)envp;
    write(1, "Filesystem    1K-blocks   Used    Available  Mounted-on\n", 56);
    int start = (argc > 1) ? 1 : 0;
    int end = (argc > 1) ? argc : 1;
    const char *def = "/";
    for (int i = start; i < end; i++) {
        const char *path = (argc > 1) ? argv[i] : def;
        struct statfs s;
        if (statfs(path, &s) < 0) continue;
        write(1, "ext4         ", 13);
        put_dec(s.f_blocks);  write(1, "    ", 4);
        put_dec(s.f_blocks - s.f_bavail); write(1, "    ", 4);
        put_dec(s.f_bavail);  write(1, "    ", 4);
        write(1, path, strlen(path));
        write(1, "\n", 1);
    }
    return 0;
}
