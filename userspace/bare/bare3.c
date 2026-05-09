// Static-musl binary with normal crt1 (NOT -nostartfiles). Same
// startup path as busybox. Just dumps argv[0] and exits.
#include <unistd.h>
#include <string.h>

int main(int argc, char** argv) {
    write(1, "BARE3-START argv0=", 18);
    if (argc >= 1 && argv[0]) {
        write(1, argv[0], strlen(argv[0]));
    } else {
        write(1, "(null)", 6);
    }
    write(1, "\n", 1);
    return 0;
}
