// /bin/getent — POSIX getent(1). v1: passwd/group/shadow only,
// reads /etc/{passwd,group,shadow}, prints either all entries
// (`getent passwd`) or the matching line (`getent passwd root`).

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

static int streq(const char *a, const char *b) {
    while (*a && *b) { if (*a != *b) return 0; a++; b++; }
    return *a == 0 && *b == 0;
}

static long write_str(long fd, const char *s) {
    long n=0; while (s[n]) n++; return sc3(SYS_write, fd, (long)s, n);
}

// Read whole file at `path` into buf (cap-sized). Returns total bytes.
static long read_file_all(const char *path, char *buf, long cap) {
    long fd = sc4(SYS_openat, AT_FDCWD, (long)path, O_RDONLY, 0);
    if (fd < 0) return -1;
    long total = 0;
    while (total < cap) {
        long n = sc3(SYS_read, fd, (long)(buf + total), cap - total);
        if (n <= 0) break;
        total += n;
    }
    sc1(SYS_close, fd);
    return total;
}

// Match `target` against the leading `name` field of `line` (up
// to first colon). Print the whole line + newline if matched.
// Returns 1 if printed, 0 otherwise.
static int try_match(const char *line, long line_len, const char *target) {
    if (target == 0) {
        sc3(SYS_write, 1, (long)line, line_len);
        sc3(SYS_write, 1, (long)"\n", 1);
        return 1;
    }
    // Walk line until ':' or end
    long i = 0;
    long t = 0;
    while (i < line_len && line[i] != ':') {
        if (target[t] != line[i]) return 0;
        i++; t++;
    }
    if (target[t] != 0) return 0;  // target is longer
    // Match — print line.
    sc3(SYS_write, 1, (long)line, line_len);
    sc3(SYS_write, 1, (long)"\n", 1);
    return 1;
}

__attribute__((force_align_arg_pointer))
void _start(void) {
    long argc; char **argv;
    __asm__ volatile ("mov (%%rsp), %0\n\t lea 8(%%rsp), %1\n\t" : "=r"(argc), "=r"(argv));
    if (argc < 2) {
        write_str(2, "getent: usage: getent <db> [key]\n");
        sc1(SYS_exit, 1);
    }
    const char *db = argv[1];
    const char *key = (argc > 2) ? argv[2] : 0;
    const char *path;
    if (streq(db, "passwd"))      path = "/etc/passwd";
    else if (streq(db, "group"))  path = "/etc/group";
    else if (streq(db, "shadow")) path = "/etc/shadow";
    else { write_str(2, "getent: unknown db\n"); sc1(SYS_exit, 1); }

    char buf[16384];
    long n = read_file_all(path, buf, sizeof(buf));
    if (n <= 0) { write_str(2, "getent: open failed\n"); sc1(SYS_exit, 1); }

    // Walk lines; for each non-comment non-empty line, try_match.
    long start = 0; int matched = 0;
    for (long i = 0; i < n; i++) {
        if (buf[i] == '\n') {
            if (i > start && buf[start] != '#') {
                if (try_match(buf + start, i - start, key)) matched = 1;
            }
            start = i + 1;
        }
    }
    sc1(SYS_exit, (key && !matched) ? 2 : 0);
    __builtin_unreachable();
}
