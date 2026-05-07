// /bin/ln — POSIX ln(1). Hardlink only (no -s for v1).
#include "../shared/oxide_start.h"
#include <unistd.h>

int main(int argc, char** argv, char** envp) {
    (void)envp;
    if (argc < 3) {
        write(2, "ln: usage: ln <target> <linkpath>\n", 34);
        return 1;
    }
    if (link(argv[1], argv[2]) < 0) {
        write(2, "ln: failed\n", 11);
        return 1;
    }
    return 0;
}
