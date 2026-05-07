// oxide-sh: minimal interactive shell against the oxide kernel's
// existing syscall surface. Static-PIE musl. Builtins:
//   help              list commands
//   echo <args>       write args back
//   ls [path]         opendir + getdents64 + print names
//   cat <path>        read file + write to stdout
//   pwd               getcwd
//   cd <path>         chdir
//   uname             uname → release string
//   exit              _exit(0)
//
// All paths resolve via the kernel's existing path lookup
// (procfs / devfs / tmpfs / ext4 / const blobs). Arch-portable
// via shared/oxide_start.h + musl libc.

#define _GNU_SOURCE
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <sys/utsname.h>
#include <sys/wait.h>

extern int pipe2(int pipefd[2], int flags);

static int streq_n(const char *a, const char *b, long n) {
    for (long i = 0; i < n; i++) if (a[i] != b[i]) return 0;
    return 1;
}
static int prefix(const char *s, long sl, const char *p) {
    long pl = strlen(p);
    if (sl < pl) return 0;
    return streq_n(s, p, pl);
}

static int out_fd = STDOUT_FILENO;
static long write_n(const char *s, long n) { return write(out_fd, s, n); }
static long write_str(const char *s) { return write_n(s, strlen(s)); }

static long read_line(char *buf, long cap) {
    long off = 0;
    while (off < cap) {
        char c;
        ssize_t n = read(0, &c, 1);
        if (n <= 0) return off;
        buf[off++] = c;
        if (c == '\n') break;
    }
    return off;
}

static void cmd_cat(const char *path) {
    int fd;
    if (path == 0 || path[0] == 0) {
        fd = 0;
    } else {
        fd = open(path, O_RDONLY);
        if (fd < 0) { write_str("cat: open failed\n"); return; }
    }
    char buf[256];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0) break;
        write_n(buf, n);
    }
    if (fd > 0) close(fd);
}

static void cmd_ls(const char *path) {
    DIR *d = opendir(path);
    if (!d) { write_str("ls: open failed\n"); return; }
    struct dirent *e;
    while ((e = readdir(d)) != 0) {
        write_str(e->d_name);
        write_str("\n");
    }
    closedir(d);
}

static void cmd_uname(void) {
    struct utsname u;
    if (uname(&u) < 0) { write_str("uname: syscall failed\n"); return; }
    write_str(u.release);
    write_str("\n");
}

static int run_one(char *seg, long seg_n) {
    long s = 0;
    while (s < seg_n && (seg[s] == ' ' || seg[s] == '\t')) s++;
    long e = seg_n;
    while (e > s && (seg[e-1] == ' ' || seg[e-1] == '\t')) e--;
    if (e == s) return 0;
    char *buf = seg + s;
    long n = e - s;
    buf[n] = 0;

    int redir_fd = -1;
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
                redir_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (redir_fd < 0) {
                    write(STDOUT_FILENO, "redir: open failed\n", 19);
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
        if (redir_fd >= 0) { close(redir_fd); out_fd = STDOUT_FILENO; }
        write(STDOUT_FILENO, "bye\n", 4);
        _exit(0);
    } else if (n == 4 && streq_n(buf, "help", 4)) {
        write_str("builtins: exit, echo, help, ls [path], cat <path>, "
                  "pwd, cd <path>, uname, exec <path>; redirection: "
                  "cmd > path; chaining: cmd1 ; cmd2\n");
    } else if (n == 3 && streq_n(buf, "pwd", 3)) {
        char p[256];
        if (getcwd(p, sizeof(p)) != 0) {
            write_str(p);
            write_str("\n");
        } else write_str("pwd: getcwd failed\n");
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
    } else if (n == 3 && streq_n(buf, "cat", 3)) {
        cmd_cat(0);
    } else if (n >= 4 && prefix(buf, n, "cat ")) {
        long i = 4;
        while (i < n && (buf[i] == ' ' || buf[i] == '\t')) i++;
        if (i >= n) cmd_cat(0); else cmd_cat(buf + i);
    } else if (n >= 5 && prefix(buf, n, "exec ")) {
        long i = 5;
        while (i < n && (buf[i] == ' ' || buf[i] == '\t')) i++;
        if (i >= n) { write_str("exec: missing path\n"); }
        else {
            char* a[1] = { 0 };
            char* e[1] = { 0 };
            execve(buf + i, a, e);
            write_str("exec: failed\n");
        }
    } else if (n >= 3 && prefix(buf, n, "cd ")) {
        long i = 2;
        while (i < n && (buf[i] == ' ' || buf[i] == '\t')) i++;
        if (i >= n) write_str("cd: missing path\n");
        else if (chdir(buf + i) < 0) write_str("cd: chdir failed\n");
    } else if (n > 0 && buf[0] == '/') {
        pid_t pid = fork();
        if (pid == 0) {
            char *argv[9];
            int argc = 0;
            long i = 0;
            while (i < n && argc < 8) {
                while (i < n && (buf[i] == ' ' || buf[i] == '\t')) {
                    buf[i] = 0; i++;
                }
                if (i >= n) break;
                argv[argc++] = buf + i;
                while (i < n && buf[i] != ' ' && buf[i] != '\t') i++;
            }
            if (i < n) buf[i] = 0;
            argv[argc] = 0;
            execve(argv[0], argv, 0);
            write(STDOUT_FILENO, "exec: failed\n", 13);
            _exit(127);
        }
        waitpid(pid, 0, 0);
    } else if (n > 0) {
        write_str("?: ");
        write_n(buf, n);
        write_str("\n");
    }

    if (redir_fd >= 0) { close(redir_fd); out_fd = STDOUT_FILENO; }
    return 0;
}

#define MAX_PIPE_SEGS 8
static void run_segment(char *seg, long n) {
    int background = 0;
    while (n > 0 && (seg[n-1] == ' ' || seg[n-1] == '\t')) n--;
    if (n > 0 && seg[n-1] == '&') {
        background = 1;
        n--;
        while (n > 0 && (seg[n-1] == ' ' || seg[n-1] == '\t')) n--;
    }
    long starts[MAX_PIPE_SEGS + 1];
    long ends  [MAX_PIPE_SEGS + 1];
    int  nseg = 0;
    long s = 0;
    for (long i = 0; i <= n; i++) {
        if (i == n || seg[i] == '|') {
            if (nseg >= MAX_PIPE_SEGS + 1) break;
            starts[nseg] = s;
            ends  [nseg] = i;
            nseg++;
            s = i + 1;
        }
    }
    if (nseg <= 1) {
        if (background) {
            pid_t pid = fork();
            if (pid == 0) { run_one(seg, n); _exit(0); }
        } else {
            run_one(seg, n);
        }
        return;
    }

    int pipes[MAX_PIPE_SEGS][2];
    for (int i = 0; i < nseg - 1; i++) {
        if (pipe2(pipes[i], 0) < 0) { write_str("pipe2: failed\n"); return; }
    }

    pid_t pids[MAX_PIPE_SEGS + 1];
    for (int i = 0; i < nseg; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            if (i > 0) dup2(pipes[i-1][0], 0);
            if (i < nseg - 1) dup2(pipes[i][1], 1);
            for (int j = 0; j < nseg - 1; j++) {
                close(pipes[j][0]);
                close(pipes[j][1]);
            }
            run_one(seg + starts[i], ends[i] - starts[i]);
            _exit(0);
        }
        pids[i] = pid;
    }

    for (int j = 0; j < nseg - 1; j++) {
        close(pipes[j][0]);
        close(pipes[j][1]);
    }
    if (!background) {
        for (int i = 0; i < nseg; i++) {
            waitpid(pids[i], 0, 0);
        }
    }
}

int main(int argc, char** argv, char** envp) {
    (void)argc; (void)argv; (void)envp;
    static const char banner[] =
        "oxide-sh: builtins exit/echo/help/ls/cat/pwd/cd/uname/exec (sep: ; redir: > pipe: |)\n";
    write_str(banner);

    char buf[256];
    for (;;) {
        char cwd[256];
        if (getcwd(cwd, sizeof(cwd)) != 0) write_str(cwd);
        else write_str("/");
        write_str("$ ");

        long n = read_line(buf, sizeof(buf) - 1);
        if (n <= 0) return 0;
        while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r')) n--;
        if (n == 0) continue;

        long start = 0;
        for (long i = 0; i <= n; i++) {
            if (i == n || buf[i] == ';') {
                run_segment(buf + start, i - start);
                start = i + 1;
            }
        }
    }
}
