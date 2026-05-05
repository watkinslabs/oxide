// oxide-sh: minimal interactive shell against the oxide kernel's
// existing syscall surface. Static-PIE musl. Builtins:
//   help              list commands
//   echo <args>       write args back
//   ls [path]         opendir + getdents64 + print names
//   cat <path>        read file + write to stdout
//   pwd               print '/' (we have no cwd yet beyond root)
//   exit              sys_exit(0)
//
// All paths resolve via the kernel's existing path lookup
// (procfs / devfs / tmpfs / hand-rolled blob lookup). The shell
// exists to prove the read+write+open syscall path end-to-end
// from real-musl userspace.

#include <sys/syscall.h>

#define O_RDONLY    0
#define O_DIRECTORY 0x10000
#define AT_FDCWD    -100

static long
sc1(long nr, long a0) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "0"(nr), "D"(a0) : "rcx","r11","memory");
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
static long write_n(const char *s, long n) { return sc3(SYS_write, 1, (long)s, n); }
static long write_str(const char *s) { return write_n(s, strlen_(s)); }

static long open_(const char *path, long flags) {
    return sc4(SYS_openat, AT_FDCWD, (long)path, flags, 0);
}
static long close_(long fd) { return sc1(SYS_close, fd); }

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
            // ino(8) off(8) reclen(2) type(1) name(reclen-19)
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

void _start(void) {
    static const char banner[] =
        "oxide-sh: builtins exit / echo / help / ls / cat / pwd\n";
    write_str(banner);

    char buf[256];
    for (;;) {
        write_str("oxide$ ");
        long n = read_line(buf, sizeof(buf) - 1);
        if (n <= 0) {
            sc1(SYS_exit, 0);
        }
        while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r')) n--;
        if (n == 0) continue;
        buf[n] = 0;

        if (n == 4 && streq_n(buf, "exit", 4)) {
            write_str("bye\n");
            sc1(SYS_exit, 0);
        }
        if (n == 4 && streq_n(buf, "help", 4)) {
            write_str("builtins: exit, echo, help, ls [path], cat <path>, pwd\n");
            continue;
        }
        if (n == 3 && streq_n(buf, "pwd", 3)) {
            write_str("/\n");
            continue;
        }
        if (n >= 4 && prefix(buf, n, "echo")) {
            long i = 4;
            while (i < n && (buf[i] == ' ' || buf[i] == '\t')) i++;
            write_n(buf + i, n - i);
            write_str("\n");
            continue;
        }
        if (n >= 2 && prefix(buf, n, "ls")) {
            long i = 2;
            while (i < n && (buf[i] == ' ' || buf[i] == '\t')) i++;
            const char *path = (i < n) ? buf + i : "/";
            cmd_ls(path);
            continue;
        }
        if (n >= 4 && prefix(buf, n, "cat ")) {
            long i = 4;
            while (i < n && (buf[i] == ' ' || buf[i] == '\t')) i++;
            if (i >= n) { write_str("cat: missing path\n"); continue; }
            cmd_cat(buf + i);
            continue;
        }
        write_str("?: ");
        write_n(buf, n);
        write_str("\n");
    }
}
