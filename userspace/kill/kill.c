// /bin/kill — POSIX signal sender. Usage:
//   kill <pid>          sends SIGTERM
//   kill -<sig> <pid>   sends signal number <sig>
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>

static long parse_int(const char *s) {
    long v = 0;
    while (*s >= '0' && *s <= '9') { v = v * 10 + (*s - '0'); s++; }
    return v;
}

int main(int argc, char** argv, char** envp) {
    (void)envp;
    long sig = SIGTERM;
    int idx = 1;
    if (argc > 1 && argv[1][0] == '-' && argv[1][1] >= '0' && argv[1][1] <= '9') {
        sig = parse_int(argv[1] + 1);
        idx++;
    }
    if (idx >= argc) {
        write(1, "kill: missing pid\n", 18);
        return 1;
    }
    long pid = parse_int(argv[idx]);
    if (kill((pid_t)pid, sig) < 0) {
        write(1, "kill: failed\n", 13);
        return 1;
    }
    return 0;
}
