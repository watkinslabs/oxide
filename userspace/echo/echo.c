// /bin/echo — POSIX echo. Joins argv[1..] with single spaces,
// writes the result + a trailing newline. -n suppresses newline.
// Arch-portable via shared/oxide_start.h + musl libc.
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <string.h>

int main(int argc, char** argv, char** envp) {
    (void)envp;
    int trailing_newline = 1;
    int i = 1;
    if (i < argc && strcmp(argv[i], "-n") == 0) { trailing_newline = 0; i++; }
    for (; i < argc; i++) {
        write(1, argv[i], strlen(argv[i]));
        if (i + 1 < argc) write(1, " ", 1);
    }
    if (trailing_newline) write(1, "\n", 1);
    return 0;
}
