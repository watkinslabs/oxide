// oxide-sh: minimal interactive shell against the oxide kernel's
// existing syscall surface. Static-PIE musl. Builtins:
//   help              list commands
//   echo <args>       write args back
//   ls [path]         opendir + getdents64 + print names
//   cat <path>        read file + write to stdout
//   pwd               sys_getcwd
//   cd <path>         sys_chdir
//   uname             sys_uname → release string
//   exit              sys_exit(0)
//
// All paths resolve via the kernel's existing path lookup
// (procfs / devfs / tmpfs / ext4 / const blobs). The shell
// proves read+write+open+chdir+getcwd+uname end-to-end from
// real-musl userspace.

#include <sys/syscall.h>

#define O_RDONLY    0
#define O_WRONLY    1
#define O_CREAT     00100
#define O_TRUNC     01000
#define O_DIRECTORY 0x10000
#define AT_FDCWD    -100
#define STDOUT_FD   1

static long
sc1(long nr, long a0) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "0"(nr), "D"(a0) : "rcx","r11","memory");
    return ret;
}
static long
sc2(long nr, long a0, long a1) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "0"(nr), "D"(a0), "S"(a1) : "rcx","r11","memory");
    return ret;
}
static long
sc3(long nr, long a0, long a1, long a2) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "0"(nr), "D"(a0), "S"(a1), "d"(a2) : "rcx","r11","memory");
    return ret;
}
static long
sc4(long nr, long a0, long a1, long a2, long a3) {
    long ret;
    register long r10 __asm__("r10") = a3;
    __asm__ volatile ("syscall" : "=a"(ret) : "0"(nr), "D"(a0), "S"(a1), "d"(a2), "r"(r10)
                      : "rcx","r11","memory");
    return ret;
}

static long strlen_(const char *s) { long n = 0; while (s[n]) n++; return n; }
static int  streq_n(const char *a, const char *b, long n) {
    for (long i=0;i<n;i++) if (a[i]!=b[i]) return 0;
    return 1;
}
static int  prefix(const char *s, long sl, const char *p) {
    long pl = strlen_(p);
    if (sl < pl) return 0;
    return streq_n(s, p, pl);
}
// Default output fd for shell prompts + builtin output. Redirection
// (`> path`) replaces this for the duration of one command.
static long out_fd = STDOUT_FD;
static long write_n(const char *s, long n) { return sc3(SYS_write, out_fd, (long)s, n); }
static long write_str(const char *s) { return write_n(s, strlen_(s)); }
static long write_to(long fd, const char *s, long n) { return sc3(SYS_write, fd, (long)s, n); }
static long write_str_stderr(const char *s) {
    long n = strlen_(s);
    return sc3(SYS_write, STDOUT_FD, (long)s, n);
}

static long open_(const char *path, long flags) {
    return sc4(SYS_openat, AT_FDCWD, (long)path, flags, 0);
}
static long close_(long fd) { return sc1(SYS_close, fd); }
static long getcwd_(char *buf, long sz) { return sc2(SYS_getcwd, (long)buf, sz); }
static long chdir_(const char *path) { return sc1(SYS_chdir, (long)path); }

// Console read returns one byte at a time per docs/28. Accumulate
// into the caller's buffer until newline / cap; return total
// bytes read INCLUDING any trailing newline (caller strips).
static long
read_line(char *buf, long cap) {
    long off = 0;
    while (off < cap) {
        char c;
        long n = sc3(SYS_read, 0, (long)&c, 1);
        if (n <= 0) return off;
        buf[off++] = c;
        if (c == '\n') break;
    }
    return off;
}

// `cat <path>`: read the file in 256-byte chunks, write each
// chunk to fd 1. Blocks indefinitely if the file is a stream.
static void
cmd_cat(const char *path) {
    long fd = open_(path, O_RDONLY);
    if (fd < 0) {
        write_str("cat: open failed\n");
        return;
    }
    char buf[256];
    for (;;) {
        long n = sc3(SYS_read, fd, (long)buf, sizeof(buf));
        if (n <= 0) break;
        write_n(buf, n);
    }
    close_(fd);
}

// linux_dirent64: ino(8) off(8) reclen(2) type(1) name(...)
// `ls <path>`: openat(O_DIRECTORY) + getdents64 loop, print
// each name on its own line.
static void
cmd_ls(const char *path) {
    long fd = open_(path, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        write_str("ls: open failed\n");
        return;
    }
    char buf[1024];
    for (;;) {
        long n = sc3(SYS_getdents64, fd, (long)buf, sizeof(buf));
        if (n <= 0) break;
        long o = 0;
        while (o < n) {
            unsigned short reclen = *(unsigned short*)(buf + o + 16);
            const char *name = buf + o + 19;
            write_str(name);
            write_str("\n");
            if (reclen == 0) break;
            o += reclen;
        }
    }
    close_(fd);
}

// Linux struct utsname: 6 × 65-byte char arrays = 390 bytes,
// canonically laid out as sysname / nodename / release /
// version / machine / domainname. We only emit `release`.
static void
cmd_uname(void) {
    char buf[6 * 65];
    for (int i = 0; i < (int)sizeof(buf); i++) buf[i] = 0;
    long r = sc1(SYS_uname, (long)buf);
    if (r < 0) {
        write_str("uname: syscall failed\n");
        return;
    }
    write_str(buf + 65 * 2);  // release at offset 130
    write_str("\n");
}

// Run a single command segment (no `;` inside). Handles `>` redirection
// + builtin dispatch. `buf` is mutable; `n` is length (no NUL guarantee).
// Returns 0 on success, nonzero on dispatch error (currently unused —
// `;` does not short-circuit).
static int
run_one(char *seg, long seg_n) {
    // Trim leading + trailing whitespace by adjusting bounds; do NOT
    // shift in place (segment lives inside the caller's line buffer
    // and earlier shifts corrupted neighbouring segments).
    long s = 0;
    while (s < seg_n && (seg[s] == ' ' || seg[s] == '\t')) s++;
    long e = seg_n;
    while (e > s && (seg[e-1] == ' ' || seg[e-1] == '\t')) e--;
    if (e == s) return 0;
    char *buf = seg + s;
    long n = e - s;
    // Builtins read `buf[i]` up to `n`; many also rely on the body
    // being NUL-terminated for paths (cat/cd) — overwrite the byte
    // at buf[n] (which is either whitespace we trimmed or the `;`
    // separator the outer split already passed).
    buf[n] = 0;

    // Parse `> path` redirection (last `>` wins; we only support one).
    long redir_fd = -1;
    for (long k = 0; k + 1 < n; k++) {
        if (buf[k] == '>') {
            buf[k] = 0;
            long m = k + 1;
            while (m < n && (buf[m] == ' ' || buf[m] == '\t')) m++;
            if (m < n) {
                char *path = buf + m;
                long pe = n;
                while (pe > m && (buf[pe-1] == ' ' || buf[pe-1] == '\t')) pe--;
                buf[pe] = 0;
                redir_fd = sc4(SYS_openat, AT_FDCWD, (long)path,
                               O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (redir_fd < 0) {
                    write_str_stderr("redir: open failed\n");
                    return 1;
                }
                out_fd = redir_fd;
                n = k;
                while (n > 0 && (buf[n-1] == ' ' || buf[n-1] == '\t')) n--;
                buf[n] = 0;
            }
            break;
        }
    }

    if (n == 4 && streq_n(buf, "exit", 4)) {
        if (redir_fd >= 0) { close_(redir_fd); out_fd = STDOUT_FD; }
        write_str_stderr("bye\n");
        sc1(SYS_exit, 0);
    } else if (n == 4 && streq_n(buf, "help", 4)) {
        write_str("builtins: exit, echo, help, ls [path], cat <path>, "
                  "pwd, cd <path>, uname; redirection: cmd > path; "
                  "chaining: cmd1 ; cmd2\n");
    } else if (n == 3 && streq_n(buf, "pwd", 3)) {
        char p[256];
        long r = getcwd_(p, sizeof(p) - 1);
        if (r > 0) {
            if (p[r - 1] == 0) r--;
            write_n(p, r);
            write_str("\n");
        } else {
            write_str("pwd: getcwd failed\n");
        }
    } else if (n == 5 && streq_n(buf, "uname", 5)) {
        cmd_uname();
    } else if (n >= 4 && prefix(buf, n, "echo")) {
        long i = 4;
        while (i < n && (buf[i] == ' ' || buf[i] == '\t')) i++;
        write_n(buf + i, n - i);
        write_str("\n");
    } else if (n >= 2 && prefix(buf, n, "ls")) {
        long i = 2;
        while (i < n && (buf[i] == ' ' || buf[i] == '\t')) i++;
        const char *path = (i < n) ? buf + i : ".";
        cmd_ls(path);
    } else if (n >= 4 && prefix(buf, n, "cat ")) {
        long i = 4;
        while (i < n && (buf[i] == ' ' || buf[i] == '\t')) i++;
        if (i >= n) { write_str("cat: missing path\n"); }
        else { cmd_cat(buf + i); }
    } else if (n >= 3 && prefix(buf, n, "cd ")) {
        long i = 2;
        while (i < n && (buf[i] == ' ' || buf[i] == '\t')) i++;
        if (i >= n) { write_str("cd: missing path\n"); }
        else {
            long r = chdir_(buf + i);
            if (r < 0) write_str("cd: chdir failed\n");
        }
    } else if (n > 0) {
        write_str("?: ");
        write_n(buf, n);
        write_str("\n");
    }

    if (redir_fd >= 0) {
        close_(redir_fd);
        out_fd = STDOUT_FD;
    }
    return 0;
}

void _start(void) {
    static const char banner[] =
        "oxide-sh: builtins exit/echo/help/ls/cat/pwd/cd/uname (sep: ; redir: >)\n";
    write_str(banner);

    char buf[256];
    for (;;) {
        char cwd[256];
        long cn = getcwd_(cwd, sizeof(cwd) - 1);
        if (cn > 0) {
            if (cwd[cn - 1] == 0) cn--;
            write_n(cwd, cn);
        } else {
            write_str("/");
        }
        write_str("$ ");

        long n = read_line(buf, sizeof(buf) - 1);
        if (n <= 0) {
            sc1(SYS_exit, 0);
        }
        while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r')) n--;
        if (n == 0) continue;

        // Split at `;` and run each segment in order. Quoting/escaping
        // not supported; `;` inside `echo` text would be treated as a
        // separator. v1 limitation, fine for builtins-only shell.
        long start = 0;
        for (long i = 0; i <= n; i++) {
            if (i == n || buf[i] == ';') {
                run_one(buf + start, i - start);
                start = i + 1;
            }
        }
    }
}
