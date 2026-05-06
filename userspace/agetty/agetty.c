// /sbin/agetty — open a tty, render /etc/issue, exec /bin/login.
//
// Usage: agetty <tty> [<baud>]
// Argv form mirrors util-linux agetty so existing /etc/inittab-shape
// configs work. baud is accepted but ignored (kernel tty has fixed
// rate). The tty arg is either an absolute path (`/dev/tty1`) or a
// short name (`tty1`); we prefix /dev/ in the latter case.
//
// Sequence:
//   1. openat the tty for r/w
//   2. close fds 0/1/2
//   3. dup the tty fd onto 0, 1, 2
//   4. read /etc/issue, expand \n / \\ / \\l / \\s tokens, write to tty
//   5. execve /bin/login with no args (it reads the username from stdin)

#include <sys/syscall.h>
#include <stdint.h>

#define O_RDWR 2
#define AT_FDCWD -100

static long sc1(long n, long a) {
    long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(n), "D"(a) : "rcx","r11","memory"); return r;
}
static long sc2(long n, long a, long b) {
    long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(n), "D"(a), "S"(b) : "rcx","r11","memory"); return r;
}
static long sc3(long n, long a, long b, long c) {
    long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(n), "D"(a), "S"(b), "d"(c) : "rcx","r11","memory"); return r;
}
static long sc4(long n, long a, long b, long c, long d) {
    long r; register long r10 __asm__("r10") = d;
    __asm__ volatile ("syscall" : "=a"(r) : "0"(n), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx","r11","memory");
    return r;
}

static long mlen(const char* s) { long n = 0; while (s[n]) n++; return n; }
static void wstr(int fd, const char* s) { sc3(SYS_write, fd, (long)s, mlen(s)); }

static int starts(const char* s, const char* p) {
    while (*p) { if (*s++ != *p++) return 0; }
    return 1;
}

static char path_buf[64];
static char issue_buf[1024];
static char out_buf[1024];

// Compose the tty path. Result lives in path_buf.
static const char* tty_path(const char* arg) {
    if (arg[0] == '/') {
        long n = mlen(arg);
        if (n >= (long)sizeof(path_buf)) return 0;
        for (long i = 0; i < n; i++) path_buf[i] = arg[i];
        path_buf[n] = 0;
    } else {
        const char* pre = "/dev/";
        long pn = mlen(pre), an = mlen(arg);
        if (pn + an >= (long)sizeof(path_buf)) return 0;
        long i = 0;
        for (; i < pn; i++) path_buf[i] = pre[i];
        for (long k = 0; k < an; k++) path_buf[i + k] = arg[k];
        path_buf[pn + an] = 0;
    }
    return path_buf;
}

// Read /etc/issue and expand backslash tokens into out_buf. Returns
// bytes written. Tokens supported (subset of util-linux):
//   \\l → tty name (after /dev/)
//   \\n → "oxide" hostname placeholder
//   \\s → "oxide" OS name
//   \\\\ → literal backslash
// Anything else after a backslash is dropped.
static long render_issue(const char* tty_short) {
    long fd = sc4(SYS_openat, AT_FDCWD, (long)"/etc/issue", 0, 0);
    if (fd < 0) {
        const char* fb = "oxide \\l\n\n";
        long n = mlen(fb);
        for (long i = 0; i < n; i++) issue_buf[i] = fb[i];
        issue_buf[n] = 0;
    } else {
        long t = 0;
        while (t < (long)sizeof(issue_buf) - 1) {
            long r = sc3(SYS_read, fd, (long)(issue_buf + t), sizeof(issue_buf) - 1 - t);
            if (r <= 0) break; t += r;
        }
        sc1(SYS_close, fd);
        issue_buf[t] = 0;
    }
    long o = 0, i = 0;
    while (issue_buf[i] && o < (long)sizeof(out_buf) - 1) {
        char c = issue_buf[i++];
        if (c != '\\' || !issue_buf[i]) { out_buf[o++] = c; continue; }
        char tok = issue_buf[i++];
        const char* sub = 0;
        if (tok == 'l')      sub = tty_short;
        else if (tok == 'n') sub = "oxide";
        else if (tok == 's') sub = "oxide";
        else if (tok == '\\') sub = "\\";
        if (sub) {
            long sl = mlen(sub);
            for (long k = 0; k < sl && o < (long)sizeof(out_buf) - 1; k++) out_buf[o++] = sub[k];
        }
    }
    return o;
}

__attribute__((force_align_arg_pointer))
void _start(void) {
    long argc; char** argv;
    __asm__ volatile ("mov (%%rsp), %0\n\t lea 8(%%rsp), %1\n\t"
                      : "=r"(argc), "=r"(argv));
    if (argc < 2) {
        wstr(2, "agetty: usage: agetty <tty> [<baud>]\n");
        sc1(SYS_exit, 1);
    }
    const char* tty_arg = argv[1];
    const char* short_name = tty_arg[0] == '/' ?
        (starts(tty_arg, "/dev/") ? tty_arg + 5 : tty_arg) : tty_arg;
    const char* path = tty_path(tty_arg);
    if (!path) { wstr(2, "agetty: tty name too long\n"); sc1(SYS_exit, 1); }

    long fd = sc4(SYS_openat, AT_FDCWD, (long)path, O_RDWR, 0);
    if (fd < 0) {
        wstr(2, "agetty: open failed: ");
        wstr(2, path); wstr(2, "\n");
        sc1(SYS_exit, 1);
    }

    // Re-bind 0/1/2.
    sc1(SYS_close, 0); sc2(SYS_dup2, fd, 0);
    sc1(SYS_close, 1); sc2(SYS_dup2, fd, 1);
    sc1(SYS_close, 2); sc2(SYS_dup2, fd, 2);
    if (fd > 2) sc1(SYS_close, fd);

    long n = render_issue(short_name);
    sc3(SYS_write, 1, (long)out_buf, n);

    char* eargv[2] = { (char*)"/bin/login", 0 };
    char* eenv[1]  = { 0 };
    sc4(SYS_execve, (long)"/bin/login", (long)eargv, (long)eenv, 0);
    wstr(2, "agetty: exec /bin/login failed\n");
    sc1(SYS_exit, 1);
    __builtin_unreachable();
}
