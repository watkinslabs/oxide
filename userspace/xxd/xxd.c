// /bin/xxd — minimal hex dump.
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <fcntl.h>

static const char HEX[16] = "0123456789abcdef";

static void put_hex8(unsigned long v, char *out) {
    for (int i = 7; i >= 0; i--) { out[i] = HEX[v & 0xF]; v >>= 4; }
}
static void put_hex2(unsigned long v, char *out) {
    out[0] = HEX[(v >> 4) & 0xF];
    out[1] = HEX[v & 0xF];
}

static void dump_fd(int fd) {
    unsigned long off = 0;
    char buf[16];
    char line[80];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0) break;
        put_hex8(off, line);
        line[8] = ':';
        line[9] = ' ';
        int p = 10;
        for (int i = 0; i < 16; i++) {
            if (i < n) { put_hex2((unsigned char)buf[i], &line[p]); }
            else       { line[p] = ' '; line[p+1] = ' '; }
            p += 2;
            if ((i & 1) == 1) line[p++] = ' ';
        }
        line[p++] = ' ';
        for (long i = 0; i < n; i++) {
            unsigned char c = (unsigned char)buf[i];
            line[p++] = (c >= 0x20 && c < 0x7F) ? c : '.';
        }
        line[p++] = '\n';
        write(1, line, p);
        off += n;
    }
}

int main(int argc, char** argv, char** envp) {
    (void)envp;
    if (argc < 2) { dump_fd(0); return 0; }
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) return 1;
    dump_fd(fd);
    close(fd);
    return 0;
}
