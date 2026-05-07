// /bin/mkdir — POSIX mkdir(2). Usage: mkdir <path> [...]
#include "../shared/oxide_start.h"
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char** argv, char** envp) {
    (void)envp;
    if (argc < 2) { write(1, "mkdir: missing operand\n", 23); return 1; }
    int rc = 0;
    for (int i = 1; i < argc; i++) {
        if (mkdir(argv[i], 0755) < 0) {
            write(1, "mkdir: failed: ", 15);
            write(1, argv[i], strlen(argv[i]));
            write(1, "\n", 1);
            rc = 1;
        }
    }
    return rc;
}
