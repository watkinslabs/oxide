// /bin/id — print uid/gid for the calling process. Without args:
// `uid=N(name) gid=M(name)`. With one arg: same shape for the named user.
// v1 prints only primary uid/gid; supplementary group walk later.
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>

static int memeq(const char* a, const char* b, long n) {
    for (long i = 0; i < n; i++) if (a[i] != b[i]) return 0;
    return 1;
}

static long read_file(const char* p, char* buf, long cap) {
    int fd = open(p, O_RDONLY);
    if (fd < 0) return -1;
    long t = 0;
    while (t < cap - 1) {
        ssize_t n = read(fd, buf + t, cap - 1 - t);
        if (n <= 0) break; t += n;
    }
    close(fd);
    buf[t] = 0; return t;
}

static int itoa10(unsigned long v, char* out) {
    char tmp[24]; int n = 0;
    if (v == 0) { out[0] = '0'; return 1; }
    while (v) { tmp[n++] = '0' + (v % 10); v /= 10; }
    for (int i = 0; i < n; i++) out[i] = tmp[n - 1 - i];
    return n;
}

static int find_line(const char* text, const char* name, char* out, long cap) {
    long nl = strlen(name); long i = 0;
    while (text[i]) {
        long s = i;
        while (text[i] && text[i] != '\n') i++;
        long len = i - s;
        if (len > nl + 1 && text[s + nl] == ':' && memeq(text + s, name, nl)) {
            if (len >= cap) return 0;
            memcpy(out, text + s, len);
            out[len] = 0; return 1;
        }
        if (text[i] == '\n') i++;
    }
    return 0;
}

static int find_by_uid_or_gid(const char* text, unsigned long want, int field, char* out, long cap) {
    // field=2 for passwd uid (uid is field index 2), field=2 for group gid
    long i = 0;
    while (text[i]) {
        long s = i;
        while (text[i] && text[i] != '\n') i++;
        long len = i - s;
        int colons = 0; long k = 0;
        while (k < len && colons < field) {
            if (text[s + k] == ':') colons++;
            k++;
        }
        if (colons == field) {
            unsigned long u = 0; long m = k; int valid = 1;
            while (m < len && text[s + m] != ':') {
                if (text[s + m] < '0' || text[s + m] > '9') { valid = 0; break; }
                u = u * 10 + (text[s + m] - '0'); m++;
            }
            if (valid && u == want) {
                if (len >= cap) return 0;
                memcpy(out, text + s, len); out[len] = 0; return 1;
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

int main(int argc, char** argv, char** envp) {
    (void)envp;
    long uid = (long)getuid();
    long gid = (long)getgid();

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
            write(2, "id: no such user\n", 17);
            return 1;
        }
    } else {
        if (find_by_uid_or_gid(passwd_buf, (unsigned long)uid, 2, line_buf, sizeof(line_buf))) {
            char* f[8]; split_colons(line_buf, f, 8);
            long ul = strlen(f[0]); memcpy(tmp, f[0], ul);
            tmp[ul] = 0; uname = tmp;
        }
    }

    char gtmp[64];
    if (find_by_uid_or_gid(group_buf, (unsigned long)gid, 2, line_buf, sizeof(line_buf))) {
        char* f[8]; split_colons(line_buf, f, 8);
        long gl = strlen(f[0]); memcpy(gtmp, f[0], gl);
        gtmp[gl] = 0; gname = gtmp;
    }

    char buf[256]; long o = 0;
    memcpy(buf + o, "uid=", 4); o += 4;
    o += itoa10((unsigned long)uid, buf + o);
    buf[o++] = '('; long n = strlen(uname); memcpy(buf + o, uname, n); o += n; buf[o++] = ')';
    memcpy(buf + o, " gid=", 5); o += 5;
    o += itoa10((unsigned long)gid, buf + o);
    buf[o++] = '('; n = strlen(gname); memcpy(buf + o, gname, n); o += n; buf[o++] = ')';
    buf[o++] = '\n';
    write(1, buf, o);
    return 0;
}
