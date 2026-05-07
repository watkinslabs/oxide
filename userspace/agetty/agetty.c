// /sbin/agetty — open a tty, render /etc/issue, exec /bin/login.
//
// Usage: agetty <tty> [<baud>]
// Argv form mirrors util-linux agetty so existing /etc/inittab-shape
// configs work. baud is accepted but ignored.
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

static int starts(const char* s, const char* p) {
    while (*p) { if (*s++ != *p++) return 0; }
    return 1;
}

static char path_buf[64];
static char issue_buf[1024];
static char out_buf[1024];

static const char* tty_path(const char* arg) {
    if (arg[0] == '/') {
        long n = strlen(arg);
        if (n >= (long)sizeof(path_buf)) return 0;
        memcpy(path_buf, arg, n);
        path_buf[n] = 0;
    } else {
        const char* pre = "/dev/";
        long pn = strlen(pre), an = strlen(arg);
        if (pn + an >= (long)sizeof(path_buf)) return 0;
        memcpy(path_buf, pre, pn);
        memcpy(path_buf + pn, arg, an);
        path_buf[pn + an] = 0;
    }
    return path_buf;
}

static long render_issue(const char* tty_short) {
    int fd = open("/etc/issue", O_RDONLY);
    if (fd < 0) {
        const char* fb = "oxide \\l\n\n";
        long n = strlen(fb);
        memcpy(issue_buf, fb, n);
        issue_buf[n] = 0;
    } else {
        long t = 0;
        while (t < (long)sizeof(issue_buf) - 1) {
            ssize_t r = read(fd, issue_buf + t, sizeof(issue_buf) - 1 - t);
            if (r <= 0) break; t += r;
        }
        close(fd);
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
            long sl = strlen(sub);
            for (long k = 0; k < sl && o < (long)sizeof(out_buf) - 1; k++) out_buf[o++] = sub[k];
        }
    }
    return o;
}

int main(int argc, char** argv, char** envp) {
    (void)envp;
    if (argc < 2) {
        write(2, "agetty: usage: agetty <tty> [<baud>]\n", 37);
        return 1;
    }
    const char* tty_arg = argv[1];
    const char* short_name = tty_arg[0] == '/' ?
        (starts(tty_arg, "/dev/") ? tty_arg + 5 : tty_arg) : tty_arg;
    const char* path = tty_path(tty_arg);
    if (!path) { write(2, "agetty: tty name too long\n", 26); return 1; }

    int fd = open(path, O_RDWR);
    if (fd < 0) {
        write(2, "agetty: open failed: ", 21);
        write(2, path, strlen(path));
        write(2, "\n", 1);
        return 1;
    }

    close(0); dup2(fd, 0);
    close(1); dup2(fd, 1);
    close(2); dup2(fd, 2);
    if (fd > 2) close(fd);

    long n = render_issue(short_name);
    write(1, out_buf, n);

    char* eargv[2] = { (char*)"/bin/login", 0 };
    char* eenv[1]  = { 0 };
    execve("/bin/login", eargv, eenv);
    write(2, "agetty: exec /bin/login failed\n", 31);
    return 1;
}
