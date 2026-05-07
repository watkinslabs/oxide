// /bin/rm — POSIX unlink(2). Usage: rm [-r] <path> [...]
// -r: rmdir on directories (single-level; doesn't recurse).
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <string.h>

int main(int argc, char** argv, char** envp) {
    (void)envp;
    int recursive = 0;
    int i = 1;
    while (i < argc && argv[i][0] == '-') {
        if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "-R") == 0 || strcmp(argv[i], "-rf") == 0) recursive = 1;
        else break;
        i++;
    }
    if (i >= argc) { write(1, "rm: missing operand\n", 20); return 1; }
    int rc = 0;
    for (; i < argc; i++) {
        int r = unlink(argv[i]);
        if (r < 0 && recursive) r = rmdir(argv[i]);
        if (r < 0) {
            write(1, "rm: failed: ", 12);
            write(1, argv[i], strlen(argv[i]));
            write(1, "\n", 1);
            rc = 1;
        }
    }
    return rc;
}
