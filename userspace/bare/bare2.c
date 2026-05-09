// Touch argv[1] — does strlen/write on it work?
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <string.h>

int main(int argc, char** argv, char** envp) {
    (void)envp;
    write(1, "BARE2-START\n", 12);
    if (argc < 2) {
        write(1, "BARE2-NO-ARG\n", 13);
        return 0;
    }
    write(1, "BARE2-ARGC-OK\n", 14);
    // Try to read argv[1] one byte at a time without strlen.
    char* p = argv[1];
    if (!p) {
        write(1, "BARE2-ARGV1-NULL\n", 17);
        return 0;
    }
    write(1, "BARE2-ARGV1-NONNULL\n", 20);
    // Dump first 16 bytes of argv[1] as 2-hex pairs so we see what's
    // really there, regardless of NUL termination. Then dump argv[0]
    // pointer + first 16 bytes for comparison.
    static const char hex[] = "0123456789abcdef";
    write(1, "BARE2-ARGV1-BYTES: ", 19);
    for (int i = 0; i < 16; i++) {
        unsigned char b = (unsigned char)p[i];
        char buf[3] = { hex[b >> 4], hex[b & 0xf], ' ' };
        write(1, buf, 3);
    }
    write(1, "\n", 1);
    write(1, "BARE2-ARGV0-BYTES: ", 19);
    char* p0 = argv[0];
    if (!p0) {
        write(1, "NULL\n", 5);
    } else {
        for (int i = 0; i < 16; i++) {
            unsigned char b = (unsigned char)p0[i];
            char buf[3] = { hex[b >> 4], hex[b & 0xf], ' ' };
            write(1, buf, 3);
        }
        write(1, "\n", 1);
    }
    // Dump argc as a single ascii digit.
    {
        char d = '0' + (char)(argc & 0xf);
        write(1, "BARE2-ARGC: ", 12);
        write(1, &d, 1);
        write(1, "\n", 1);
    }
    return 0;
}
