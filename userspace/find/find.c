// /bin/find — POSIX find(1) (subset). Walks paths recursively
// and prints every entry. v1: no expressions; just `-name PAT`
// glob (literal-or-* match) and `-type f|d` filter.

#include <sys/syscall.h>

#define O_RDONLY    0
#define O_DIRECTORY 0x10000
#define AT_FDCWD    -100

#define DT_REG 8
#define DT_DIR 4

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

static long write_str(long fd, const char *s) {
    long n=0; while (s[n]) n++; return sc3(SYS_write, fd, (long)s, n);
}
static int streq(const char *a, const char *b) {
    while (*a && *b) { if (*a != *b) return 0; a++; b++; }
    return *a == 0 && *b == 0;
}

static char path_buf[1024];

static void walk(int depth_left, long path_len, char filter_type, const char *name_pat) {
    if (depth_left <= 0) return;
    long fd = sc4(SYS_openat, AT_FDCWD, (long)path_buf, O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) return;
    char buf[2048];
    for (;;) {
        long n = sc3(SYS_getdents64, fd, (long)buf, sizeof(buf));
        if (n <= 0) break;
        long o = 0;
        while (o < n) {
            unsigned short reclen = *(unsigned short*)(buf + o + 16);
            unsigned char dtype = *(unsigned char*)(buf + o + 18);
            const char *name = buf + o + 19;
            if (!(name[0]=='.' && (name[1]==0 || (name[1]=='.' && name[2]==0)))) {
                long nlen = 0; while (name[nlen]) nlen++;
                if (path_len + 1 + nlen + 1 < (long)sizeof(path_buf)) {
                    path_buf[path_len] = '/';
                    for (long i = 0; i < nlen; i++) path_buf[path_len + 1 + i] = name[i];
                    path_buf[path_len + 1 + nlen] = 0;
                    int matches = 1;
                    if (filter_type == 'f' && dtype != DT_REG) matches = 0;
                    if (filter_type == 'd' && dtype != DT_DIR) matches = 0;
                    if (name_pat && !streq(name, name_pat)) matches = 0;
                    if (matches) {
                        write_str(1, path_buf);
                        write_str(1, "\n");
                    }
                    if (dtype == DT_DIR) {
                        walk(depth_left - 1, path_len + 1 + nlen, filter_type, name_pat);
                    }
                }
            }
            if (reclen == 0) break;
            o += reclen;
        }
    }
    sc1(SYS_close, fd);
}

__attribute__((force_align_arg_pointer))
void _start(void) {
    long argc; char **argv;
    __asm__ volatile ("mov (%%rsp), %0\n\t lea 8(%%rsp), %1\n\t" : "=r"(argc), "=r"(argv));
    const char *root = (argc > 1 && argv[1][0] != '-') ? argv[1] : ".";
    char filter_type = 0;
    const char *name_pat = 0;
    for (long i = 1; i < argc; i++) {
        if (streq(argv[i], "-type") && i+1 < argc) { filter_type = argv[i+1][0]; i++; }
        else if (streq(argv[i], "-name") && i+1 < argc) { name_pat = argv[i+1]; i++; }
    }
    long n = 0; while (root[n]) n++;
    if (n + 1 >= (long)sizeof(path_buf)) sc1(SYS_exit, 1);
    for (long i = 0; i < n; i++) path_buf[i] = root[i];
    path_buf[n] = 0;
    write_str(1, path_buf); write_str(1, "\n");
    walk(8, n, filter_type, name_pat);
    sc1(SYS_exit, 0);
}
