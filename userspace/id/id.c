// /bin/id — print uid/gid for the calling process. Without args:
// `uid=N(name) gid=M(name) groups=...`. With one arg: same shape
// but for the named user (read /etc/passwd; lookup gid in
// /etc/group). v1 prints only primary uid/gid; supplementary
// group walk lands when getgrouplist exists.

#include <sys/syscall.h>

#define O_RDONLY 0
#define AT_FDCWD -100

static long sc1(long n, long a) {
    long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(n), "D"(a) : "rcx","r11","memory"); return r;
}
static long sc3(long n, long a, long b, long c) {
    long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(n), "D"(a), "S"(b), "d"(c) : "rcx","r11","memory"); return r;
}
static long sc4(long n, long a, long b, long c, long d) {
    long r; register long r10 __asm__("r10") = d;
    __asm__ volatile ("syscall" : "=a"(r) : "0"(n), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx","r11","memory");
    return r;
}

static long mlen(const char* s) { long n=0; while (s[n]) n++; return n; }
static void wstr(long fd, const char* s) { sc3(SYS_write, fd, (long)s, mlen(s)); }

static int streq(const char* a, const char* b) {
    while (*a && *b && *a == *b) { a++; b++; }
    return *a == 0 && *b == 0;
}
static int memeq(const char* a, const char* b, long n) {
    for (long i = 0; i < n; i++) if (a[i] != b[i]) return 0;
    return 1;
}

static long read_file(const char* p, char* buf, long cap) {
    long fd = sc4(SYS_openat, AT_FDCWD, (long)p, O_RDONLY, 0);
    if (fd < 0) return -1;
    long t = 0;
    while (t < cap - 1) {
        long n = sc3(SYS_read, fd, (long)(buf + t), cap - 1 - t);
        if (n <= 0) break; t += n;
    }
    sc1(SYS_close, fd);
    buf[t] = 0; return t;
}

// itoa for small unsigned. Returns chars written (no NUL).
static int itoa10(unsigned long v, char* out) {
    char tmp[24]; int n = 0;
    if (v == 0) { out[0] = '0'; return 1; }
    while (v) { tmp[n++] = '0' + (v % 10); v /= 10; }
    for (int i = 0; i < n; i++) out[i] = tmp[n - 1 - i];
    return n;
}

// Find passwd/group line by name; copy into out.
static int find_line(const char* text, const char* name, char* out, long cap) {
    long nl = mlen(name); long i = 0;
    while (text[i]) {
        long s = i;
        while (text[i] && text[i] != '\n') i++;
        long len = i - s;
        if (len > nl + 1 && text[s + nl] == ':' && memeq(text + s, name, nl)) {
            if (len >= cap) return 0;
            for (long k = 0; k < len; k++) out[k] = text[s + k];
            out[len] = 0; return 1;
        }
        if (text[i] == '\n') i++;
    }
    return 0;
}

// Find passwd line by uid (decimal field 3).
static int find_by_uid(const char* text, unsigned long uid, char* out, long cap) {
    long i = 0;
    while (text[i]) {
        long s = i;
        while (text[i] && text[i] != '\n') i++;
        long len = i - s;
        // skip past two colons to reach uid field.
        int colons = 0; long k = 0;
        while (k < len && colons < 2) {
            if (text[s + k] == ':') colons++;
            k++;
        }
        if (colons == 2) {
            unsigned long u = 0; long m = k;
            while (m < len && text[s + m] != ':') {
                if (text[s + m] < '0' || text[s + m] > '9') { u = ~0UL; break; }
                u = u * 10 + (text[s + m] - '0'); m++;
            }
            if (u == uid) {
                if (len >= cap) return 0;
                for (long j = 0; j < len; j++) out[j] = text[s + j];
                out[len] = 0; return 1;
            }
        }
        if (text[i] == '\n') i++;
    }
    return 0;
}

static int split_colons(char* line, char** f, int max) {
    int n = 0; f[n++] = line;
    for (long i = 0; line[i]; i++) {
        if (line[i] == ':') { line[i] = 0; if (n < max) f[n++] = &line[i+1]; }
    }
    return n;
}

static unsigned long parse_uint(const char* s) {
    unsigned long v = 0;
    while (*s >= '0' && *s <= '9') { v = v*10 + (*s - '0'); s++; }
    return v;
}

static char passwd_buf[8192], group_buf[8192], line_buf[512];

static int find_group_by_gid(const char* text, unsigned long gid, char* out, long cap) {
    long i = 0;
    while (text[i]) {
        long s = i;
        while (text[i] && text[i] != '\n') i++;
        long len = i - s;
        // group line: name:passwd:gid:members
        int colons = 0; long k = 0;
        while (k < len && colons < 2) {
            if (text[s + k] == ':') colons++;
            k++;
        }
        if (colons == 2) {
            unsigned long g = 0; long m = k;
            while (m < len && text[s + m] != ':') {
                if (text[s + m] < '0' || text[s + m] > '9') { g = ~0UL; break; }
                g = g * 10 + (text[s + m] - '0'); m++;
            }
            if (g == gid) {
                if (len >= cap) return 0;
                for (long j = 0; j < len; j++) out[j] = text[s + j];
                out[len] = 0; return 1;
            }
        }
        if (text[i] == '\n') i++;
    }
    return 0;
}

__attribute__((force_align_arg_pointer))
void _start(void) {
    long argc; char** argv;
    __asm__ volatile ("mov (%%rsp), %0\n\t lea 8(%%rsp), %1\n\t"
                      : "=r"(argc), "=r"(argv));

    long uid = sc1(SYS_getuid, 0);
    long gid = sc1(SYS_getgid, 0);

    read_file("/etc/passwd", passwd_buf, sizeof(passwd_buf));
    read_file("/etc/group",  group_buf,  sizeof(group_buf));

    const char* uname = "?";
    const char* gname = "?";
    char tmp[64];

    if (argc >= 2 && argv[1] && argv[1][0]) {
        if (find_line(passwd_buf, argv[1], line_buf, sizeof(line_buf))) {
            char* f[8]; split_colons(line_buf, f, 8);
            uname = f[0];
            uid = (long)parse_uint(f[2]);
            gid = (long)parse_uint(f[3]);
        } else {
            wstr(2, "id: no such user\n");
            sc1(SYS_exit, 1);
        }
    } else {
        if (find_by_uid(passwd_buf, (unsigned long)uid, line_buf, sizeof(line_buf))) {
            char* f[8]; split_colons(line_buf, f, 8);
            // copy uname into tmp since line_buf is reused below
            long ul = mlen(f[0]); for (long i = 0; i < ul; i++) tmp[i] = f[0][i];
            tmp[ul] = 0; uname = tmp;
            // uid/gid already from syscall; trust them.
        }
    }

    char gtmp[64];
    if (find_group_by_gid(group_buf, (unsigned long)gid, line_buf, sizeof(line_buf))) {
        char* f[8]; split_colons(line_buf, f, 8);
        long gl = mlen(f[0]); for (long i = 0; i < gl; i++) gtmp[i] = f[0][i];
        gtmp[gl] = 0; gname = gtmp;
    }

    char buf[256]; long o = 0;
    const char* p; long n;
    p = "uid="; n = mlen(p); for (long i = 0; i < n; i++) buf[o++] = p[i];
    o += itoa10((unsigned long)uid, buf + o);
    buf[o++] = '('; n = mlen(uname); for (long i = 0; i < n; i++) buf[o++] = uname[i]; buf[o++] = ')';
    p = " gid="; n = mlen(p); for (long i = 0; i < n; i++) buf[o++] = p[i];
    o += itoa10((unsigned long)gid, buf + o);
    buf[o++] = '('; n = mlen(gname); for (long i = 0; i < n; i++) buf[o++] = gname[i]; buf[o++] = ')';
    buf[o++] = '\n';
    sc3(SYS_write, 1, (long)buf, o);
    sc1(SYS_exit, 0);
}
