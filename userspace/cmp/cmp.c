// /bin/cmp — POSIX cmp(1). Exit 0 if identical, 1 if differ, 2 on I/O error.
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char** argv, char** envp) {
    (void)envp;
    if (argc < 3) { write(2, "cmp: usage: cmp <a> <b>\n", 24); return 2; }
    int a = open(argv[1], O_RDONLY);
    int b = open(argv[2], O_RDONLY);
    if (a < 0 || b < 0) { write(2, "cmp: open failed\n", 17); return 2; }
    char ba[4096], bb[4096];
    for (;;) {
        ssize_t na = read(a, ba, sizeof(ba));
        ssize_t nb = read(b, bb, sizeof(bb));
        if (na < 0 || nb < 0) return 2;
        if (na != nb) return 1;
        if (na == 0) return 0;
        for (long i = 0; i < na; i++) {
            if (ba[i] != bb[i]) { write(1, "cmp: differ\n", 12); return 1; }
        }
    }
}
