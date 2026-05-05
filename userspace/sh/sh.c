// Minimal interactive shell for Phase 5 closure. Static-PIE
// musl binary that prints "oxide$ ", reads a line from fd 0
// (the kernel console), echoes it back to fd 1, loops. Three
// builtins:
//   exit         — sys_exit(0)
//   echo <args>  — write the args back
//   help         — list builtins
//
// Real busybox-sh integration replaces this with the actual
// busybox binary built against our musl fork once `xtask user`
// can produce one.

#include <sys/syscall.h>

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
write_str(const char *s) {
    long n = 0;
    while (s[n]) n++;
    return sc3(SYS_write, 1, (long)s, n);
}

static long
write_n(const char *s, long n) {
    return sc3(SYS_write, 1, (long)s, n);
}

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

static int
streq_n(const char *a, const char *b, long n) {
    for (long i = 0; i < n; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

static long
strlen_(const char *s) {
    long n = 0;
    while (s[n]) n++;
    return n;
}

void _start(void) {
    static const char banner[] = "oxide-sh: tiny shell — `exit` to halt, `echo`/`help` builtins.\n";
    write_n(banner, sizeof(banner) - 1);

    char buf[256];
    for (;;) {
        write_str("oxide$ ");
        long n = read_line(buf, sizeof(buf) - 1);
        if (n <= 0) {
            // EOF or error — exit cleanly.
            sc1(SYS_exit, 0);
        }
        // Strip trailing newline.
        while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r')) n--;
        if (n == 0) continue;
        buf[n] = 0;

        // Builtin: exit
        if (n == 4 && streq_n(buf, "exit", 4)) {
            write_str("bye\n");
            sc1(SYS_exit, 0);
        }
        // Builtin: help
        if (n == 4 && streq_n(buf, "help", 4)) {
            write_str("builtins: exit, echo, help\n");
            continue;
        }
        // Builtin: echo <args>
        if (n >= 4 && streq_n(buf, "echo", 4)) {
            // Skip past "echo" + spaces.
            long i = 4;
            while (i < n && (buf[i] == ' ' || buf[i] == '\t')) i++;
            write_n(buf + i, n - i);
            write_str("\n");
            continue;
        }
        // Unknown — echo "?: <input>\n".
        write_str("?: ");
        write_n(buf, n);
        write_str("\n");
    }
}
