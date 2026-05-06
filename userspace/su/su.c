// /bin/su — switch user. Usage: `su [<target>]`. Defaults to root.
// Prompts for the target's password from stdin, verifies against
// /etc/shadow, then execve()s the target's login shell.
//
// Identical password-verification flow to /bin/login (mirrors
// crypt crate v1: sha512(salt|password|salt) → crypt-base64).
// Stays self-contained (embedded SHA-512) until shared crypt
// lands in P14-07.

#include <sys/syscall.h>
#include <stdint.h>

static long sc1(long n, long a) {
    long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(n), "D"(a) : "rcx","r11","memory"); return r;
}
static long sc3(long n, long a, long b, long c) {
    long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(n), "D"(a), "S"(b), "d"(c) : "rcx","r11","memory"); return r;
}
static long sc4(long n, long a, long b, long c, long d) {
    long r;
    register long r10 __asm__("r10") = d;
    __asm__ volatile ("syscall" : "=a"(r) : "0"(n), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx","r11","memory");
    return r;
}

static long mlen(const char* s) { long n = 0; while (s[n]) n++; return n; }
static void wstr(int fd, const char* s) { sc3(SYS_write, fd, (long)s, mlen(s)); }
static int  open_ro(const char* p) { return (int)sc3(SYS_open, (long)p, 0, 0); }
static long readall(int fd, char* buf, long cap) {
    long t = 0;
    while (t < cap - 1) {
        long n = sc3(SYS_read, fd, (long)(buf + t), cap - 1 - t);
        if (n <= 0) break; t += n;
    }
    buf[t] = 0; return t;
}
static int memeq(const char* a, const char* b, long n) {
    for (long i = 0; i < n; i++) if (a[i] != b[i]) return 0;
    return 1;
}
static int streq(const char* a, const char* b) {
    while (*a && *b && *a == *b) { a++; b++; }
    return *a == 0 && *b == 0;
}
static int read_line(int fd, char* dst, long cap) {
    long n = 0;
    while (n < cap - 1) {
        char c; long r = sc3(SYS_read, fd, (long)&c, 1);
        if (r <= 0) break;
        if (c == '\n') break;
        dst[n++] = c;
    }
    dst[n] = 0; return (int)n;
}

#include "../shared/sha512crypt.h"


static int find_user_line(const char* text, const char* name, char* out, long cap) {
    long nl = mlen(name); long i = 0;
    while (text[i]) {
        long start = i;
        while (text[i] && text[i] != '\n') i++;
        long lnlen = i - start;
        if (lnlen > nl + 1 && text[start + nl] == ':' && memeq(text + start, name, nl)) {
            if (lnlen >= cap) return 0;
            for (long k = 0; k < lnlen; k++) out[k] = text[start + k];
            out[lnlen] = 0;
            return 1;
        }
        if (text[i] == '\n') i++;
    }
    return 0;
}

static int split_colons(char* line, char** fields, int max) {
    int n = 0; fields[n++] = line;
    for (long i = 0; line[i]; i++) {
        if (line[i] == ':') { line[i] = 0; if (n < max) fields[n++] = &line[i+1]; }
    }
    return n;
}

static char passwd_buf[8192], shadow_buf[8192], user_line[512];
static char pw_input[128], hash_out[128];

__attribute__((force_align_arg_pointer))
void _start(void) {
    long argc; char** argv;
    __asm__ volatile ("mov (%%rsp), %0\n\t lea 8(%%rsp), %1\n\t"
                      : "=r"(argc), "=r"(argv));
    const char* target = "root";
    if (argc >= 2 && argv[1] && argv[1][0]) target = argv[1];

    wstr(1, "Password: ");
    read_line(0, pw_input, sizeof(pw_input));

    int sfd = open_ro("/etc/shadow");
    if (sfd < 0) { wstr(2, "su: no /etc/shadow\n"); sc1(SYS_exit, 1); }
    readall(sfd, shadow_buf, sizeof(shadow_buf));
    sc1(SYS_close, sfd);

    int pfd = open_ro("/etc/passwd");
    if (pfd < 0) { wstr(2, "su: no /etc/passwd\n"); sc1(SYS_exit, 1); }
    readall(pfd, passwd_buf, sizeof(passwd_buf));
    sc1(SYS_close, pfd);

    if (!find_user_line(shadow_buf, target, user_line, sizeof(user_line))) {
        wstr(2, "su: unknown user\n"); sc1(SYS_exit, 1);
    }
    char* sf[8];
    int sn = split_colons(user_line, sf, 8);
    if (sn < 2) { wstr(2, "su: shadow malformed\n"); sc1(SYS_exit, 1); }
    char* hash = sf[1];

    if (hash[0] == 0) {
        if (pw_input[0] != 0) { wstr(2, "su: incorrect password\n"); sc1(SYS_exit, 1); }
    } else if (hash[0] == '!' || hash[0] == '*') {
        wstr(2, "su: account locked\n"); sc1(SYS_exit, 1);
    } else if (hash[0] == '$' && hash[1] == '6' && hash[2] == '$') {
        long i = 3;
        while (hash[i] && hash[i] != '$') i++;
        if (!hash[i]) { wstr(2, "su: incorrect password\n"); sc1(SYS_exit, 1); }
        hash[i] = 0;
        char* salt = &hash[3];
        char* expected = &hash[i+1];
        long got = sha512crypt(pw_input, salt, 5000, hash_out);
        hash_out[got] = 0;
        if (!streq(hash_out, expected)) {
            wstr(2, "su: incorrect password\n"); sc1(SYS_exit, 1);
        }
    } else {
        wstr(2, "su: unsupported hash format\n"); sc1(SYS_exit, 1);
    }

    if (!find_user_line(passwd_buf, target, user_line, sizeof(user_line))) {
        wstr(2, "su: passwd entry missing\n"); sc1(SYS_exit, 1);
    }
    char* pf[8];
    int pn = split_colons(user_line, pf, 8);
    if (pn < 7) { wstr(2, "su: passwd malformed\n"); sc1(SYS_exit, 1); }
    char* shell = pf[6];

    char* eargv[2] = { shell, 0 };
    char* eenv[1] = { 0 };
    sc4(SYS_execve, (long)shell, (long)eargv, (long)eenv, 0);
    wstr(2, "su: exec failed\n");
    sc1(SYS_exit, 1);
}
