// /bin/xxd — minimal hex dump. Reads stdin or path; outputs
// "<offset 8 hex>: <16 bytes hex>  <ascii>"

#include <sys/syscall.h>

#define O_RDONLY 0
#define AT_FDCWD -100

static long
sc1(long nr, long a0) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0) : "rcx","r11","memory"); return r; }
static long
sc3(long nr, long a0, long a1, long a2) { long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0), "S"(a1), "d"(a2) : "rcx","r11","memory"); return r; }
static long
sc4(long nr, long a0, long a1, long a2, long a3) {
    long r; register long r10 __asm__("r10") = a3;
    __asm__ volatile ("syscall" : "=a"(r) : "0"(nr), "D"(a0), "S"(a1), "d"(a2), "r"(r10) : "rcx","r11","memory");
    return r;
}

static const char HEX[16] = "0123456789abcdef";

static void put_hex8(unsigned long v, char *out) {
    for (int i = 7; i >= 0; i--) { out[i] = HEX[v & 0xF]; v >>= 4; }
}
static void put_hex2(unsigned long v, char *out) {
    out[0] = HEX[(v >> 4) & 0xF];
    out[1] = HEX[v & 0xF];
}

static void dump_fd(long fd) {
    unsigned long off = 0;
    char buf[16];
    char line[80];
    for (;;) {
        long n = sc3(SYS_read, fd, (long)buf, sizeof(buf));
        if (n <= 0) break;
        // Offset
        put_hex8(off, line);
        line[8] = ':';
        line[9] = ' ';
        // Hex pairs (16 max), with a space every 2 bytes.
        int p = 10;
        for (int i = 0; i < 16; i++) {
            if (i < n) { put_hex2((unsigned char)buf[i], &line[p]); }
            else       { line[p] = ' '; line[p+1] = ' '; }
            p += 2;
            if ((i & 1) == 1) line[p++] = ' ';
        }
        line[p++] = ' ';
        // ASCII
        for (long i = 0; i < n; i++) {
            unsigned char c = (unsigned char)buf[i];
            line[p++] = (c >= 0x20 && c < 0x7F) ? c : '.';
        }
        line[p++] = '\n';
        sc3(SYS_write, 1, (long)line, p);
        off += n;
    }
}

__attribute__((force_align_arg_pointer))
void _start(void) {
    long argc; char **argv;
    __asm__ volatile ("mov (%%rsp), %0\n\t lea 8(%%rsp), %1\n\t" : "=r"(argc), "=r"(argv));
    if (argc < 2) { dump_fd(0); sc1(SYS_exit, 0); }
    long fd = sc4(SYS_openat, AT_FDCWD, (long)argv[1], O_RDONLY, 0);
    if (fd < 0) sc1(SYS_exit, 1);
    dump_fd(fd);
    sc1(SYS_close, fd);
    sc1(SYS_exit, 0);
}
