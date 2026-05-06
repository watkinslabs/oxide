// /bin/login — read username from argv[1] (or prompt), read
// password from stdin, look up /etc/passwd + /etc/shadow, verify
// the hash, then execve(getpw->shell). Matches the v1
// crypt-stub: sha512(salt|password|salt) base64-encoded with
// the crypt(3) alphabet.
//
// On success: execve("/bin/sh", argv=[user_shell], envp=[]).
// On any failure: write "Login incorrect\n" to stderr, exit(1).

#include <sys/syscall.h>
#include <stdint.h>
#include <stddef.h>

// ---- syscall helpers --------------------------------------------------

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

static void wstr(int fd, const char* s) {
    long n = 0; while (s[n]) n++;
    sc3(SYS_write, fd, (long)s, n);
}

static int  open_ro(const char* p) { return (int)sc3(SYS_open, (long)p, 0, 0); }
static long readall(int fd, char* buf, long cap) {
    long total = 0;
    while (total < cap - 1) {
        long n = sc3(SYS_read, fd, (long)(buf + total), cap - 1 - total);
        if (n <= 0) break;
        total += n;
    }
    buf[total] = 0;
    return total;
}
static int streq(const char* a, const char* b) {
    while (*a && *b && *a == *b) { a++; b++; }
    return *a == 0 && *b == 0;
}
static int memeq(const char* a, const char* b, long n) {
    for (long i = 0; i < n; i++) if (a[i] != b[i]) return 0;
    return 1;
}
static long mlen(const char* s) { long n = 0; while (s[n]) n++; return n; }

#include "../shared/sha512crypt.h"


// ---- /etc/shadow + /etc/passwd lookup --------------------------------

// Find the line in `text` that begins with `name:`. Copies the
// line into out (NUL-terminated). Returns 1 if found.
static int find_user_line(const char* text, const char* name, char* out, long cap) {
    long nl = mlen(name);
    long i = 0;
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

// Split colon-separated line in place. Returns count of fields,
// fills fields[] with pointers into the line.
static int split_colons(char* line, char** fields, int max) {
    int n = 0; fields[n++] = line;
    for (long i = 0; line[i]; i++) {
        if (line[i] == ':') {
            line[i] = 0;
            if (n < max) fields[n++] = &line[i+1];
        }
    }
    return n;
}

// ---- main login flow --------------------------------------------------

static char passwd_buf[8192];
static char shadow_buf[8192];
static char user_line[512];
static char user_input[64];
static char pw_input[128];
static char hash_out[128];

static int read_line(int fd, char* dst, long cap) {
    long n = 0;
    while (n < cap - 1) {
        char c;
        long r = sc3(SYS_read, fd, (long)&c, 1);
        if (r <= 0) break;
        if (c == '\n') break;
        dst[n++] = c;
    }
    dst[n] = 0;
    return (int)n;
}

__attribute__((force_align_arg_pointer))
void _start(void) {
    // 1. Greet + read username from stdin.
    wstr(1, "oxide login: ");
    int ulen = read_line(0, user_input, sizeof(user_input));
    if (ulen <= 0) { wstr(2, "Login incorrect\n"); sc1(SYS_exit, 1); }

    wstr(1, "Password: ");
    int plen = read_line(0, pw_input, sizeof(pw_input));
    (void)plen;

    // 2. Load /etc/passwd + /etc/shadow.
    int pfd = open_ro("/etc/passwd");
    if (pfd < 0) { wstr(2, "no /etc/passwd\n"); sc1(SYS_exit, 1); }
    readall(pfd, passwd_buf, sizeof(passwd_buf));
    sc1(SYS_close, pfd);

    int sfd = open_ro("/etc/shadow");
    if (sfd < 0) { wstr(2, "no /etc/shadow\n"); sc1(SYS_exit, 1); }
    readall(sfd, shadow_buf, sizeof(shadow_buf));
    sc1(SYS_close, sfd);

    // 3. Look up user in /etc/shadow.
    if (!find_user_line(shadow_buf, user_input, user_line, sizeof(user_line))) {
        wstr(2, "Login incorrect\n"); sc1(SYS_exit, 1);
    }
    char* sf[8];
    int sn = split_colons(user_line, sf, 8);
    if (sn < 2) { wstr(2, "Login incorrect\n"); sc1(SYS_exit, 1); }
    char* hash = sf[1];

    // Empty hash → no password configured.
    if (hash[0] == 0) {
        if (pw_input[0] == 0) { /* allow */ }
        else                  { wstr(2, "Login incorrect\n"); sc1(SYS_exit, 1); }
    } else if (hash[0] == '!' || hash[0] == '*') {
        wstr(2, "Account locked\n"); sc1(SYS_exit, 1);
    } else if (hash[0] == '$' && hash[1] == '6' && hash[2] == '$') {
        // Find the second `$` separator.
        long i = 3;
        while (hash[i] && hash[i] != '$') i++;
        if (!hash[i]) { wstr(2, "Login incorrect\n"); sc1(SYS_exit, 1); }
        hash[i] = 0;
        char* salt = &hash[3];
        char* expected = &hash[i+1];
        long got = sha512crypt(pw_input, salt, 5000, hash_out);
        hash_out[got] = 0;
        if (!streq(hash_out, expected)) {
            wstr(2, "Login incorrect\n"); sc1(SYS_exit, 1);
        }
    } else {
        wstr(2, "Unsupported hash format\n"); sc1(SYS_exit, 1);
    }

    // 4. Look up shell in /etc/passwd, exec it.
    if (!find_user_line(passwd_buf, user_input, user_line, sizeof(user_line))) {
        wstr(2, "Login incorrect\n"); sc1(SYS_exit, 1);
    }
    char* pf[8];
    int pn = split_colons(user_line, pf, 8);
    if (pn < 7) { wstr(2, "Login incorrect\n"); sc1(SYS_exit, 1); }
    char* shell = pf[6];

    wstr(1, "Welcome to oxide.\n");
    char* argv[2] = { shell, 0 };
    char* envp[1] = { 0 };
    sc4(SYS_execve, (long)shell, (long)argv, (long)envp, 0);
    wstr(2, "exec failed\n");
    sc1(SYS_exit, 1);
}
