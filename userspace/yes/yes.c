// /bin/yes — POSIX yes(1). Writes argv[1] (default "y") + newline forever.
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <string.h>

int main(int argc, char** argv, char** envp) {
    (void)envp;
    const char *msg = (argc > 1) ? argv[1] : "y";
    size_t n = strlen(msg);
    char buf[128];
    size_t len = 0;
    while (len + n + 1 < sizeof(buf)) {
        memcpy(buf + len, msg, n);
        buf[len + n] = '\n';
        len += n + 1;
    }
    for (;;) {
        if (write(1, buf, len) <= 0) break;
    }
    return 0;
}
