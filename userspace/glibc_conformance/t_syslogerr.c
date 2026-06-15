/* <syslog.h> mask macros + setlogmask sequencing; <err.h> + <error.h> via
 * captured stderr. Output is byte-identical between host glibc and ours. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <errno.h>
#include <syslog.h>
#include <err.h>
#include <error.h>

extern char *program_invocation_name;
extern char *program_invocation_short_name;

/* Run `fn` in a child with stderr redirected into a pipe; print whatever it
 * wrote to stdout, prefixed by `tag`. fn() may call exit() (err/errx). */
static void capture(const char *tag, void (*fn)(void)) {
    int p[2];
    if (pipe(p) != 0) { perror("pipe"); exit(2); }
    fflush(stdout);   /* don't let the child inherit our stdout buffer */
    pid_t pid = fork();
    if (pid == 0) {
        dup2(p[1], 2);      /* stderr -> pipe write end */
        close(p[0]); close(p[1]);
        fn();
        _exit(0);
    }
    close(p[1]);
    char buf[1024]; ssize_t n; size_t off = 0;
    while ((n = read(p[0], buf + off, sizeof buf - 1 - off)) > 0) {
        off += (size_t)n; if (off >= sizeof buf - 1) break;
    }
    buf[off] = 0;
    close(p[0]);
    int st; waitpid(pid, &st, 0);
    printf("%s: %s", tag, buf);
}

static void f_warn(void)  { errno = EACCES;  warn("open %s", "/etc/passwd"); }
static void f_warnx(void) { errno = EACCES;  warnx("count=%d", 7); }
static void f_verr(void)  { errno = ENOENT;  errx(3, "fatal %s", "boom"); }
static void f_err(void)   { errno = EPERM;   err(4, "cannot %s", "stat"); }
static void f_error(void) { error(0, ENOSPC, "disk %s full", "sda1"); }
static void f_errorl(void){ error(0, 0, "plain %d", 42); }
static void f_erratl(void){ error_at_line(0, EINVAL, "src.c", 17, "bad %s", "arg"); }

int main(void) {
    /* --- syslog mask macros (deterministic, no network) --- */
    printf("LOG_MASK(LOG_ERR)=%d\n", LOG_MASK(LOG_ERR));
    printf("LOG_MASK(LOG_DEBUG)=%d\n", LOG_MASK(LOG_DEBUG));
    printf("LOG_UPTO(LOG_WARNING)=%d\n", LOG_UPTO(LOG_WARNING));
    printf("LOG_UPTO(LOG_DEBUG)=%d\n", LOG_UPTO(LOG_DEBUG));
    printf("LOG_PRI(LOG_LOCAL0|LOG_ERR)=%d\n", LOG_PRI(LOG_LOCAL0|LOG_ERR));
    printf("LOG_FAC(LOG_LOCAL0|LOG_ERR)=%d\n", LOG_FAC(LOG_LOCAL0|LOG_ERR));
    printf("LOG_MAKEPRI=%d\n", LOG_MAKEPRI(LOG_LOCAL1, LOG_INFO));

    /* setlogmask: returns previous mask; 0 queries without changing. */
    openlog("t_syslogerr", LOG_PID, LOG_USER);
    int m0 = setlogmask(0);                 /* query default */
    int m1 = setlogmask(LOG_UPTO(LOG_ERR)); /* set, return old */
    int m2 = setlogmask(0);                 /* query new */
    int m3 = setlogmask(m0);                /* restore, return prev */
    printf("setlogmask q=%d set=%d new=%d restore=%d\n", m0, m1, m2, m3);
    closelog();

    /* --- err/error: pin progname so both libcs print the same prefix.
     * err/warn use the short name; error()/error_at_line() use the full
     * name (program_invocation_name) — pin both to the same literal. --- */
    program_invocation_short_name = (char *)"prog";
    program_invocation_name = (char *)"prog";

    capture("warn ",  f_warn);
    capture("warnx",  f_warnx);
    capture("errx ",  f_verr);
    capture("err  ",  f_err);
    capture("error",  f_error);
    capture("errl ",  f_errorl);
    capture("eratl", f_erratl);
    return 0;
}
