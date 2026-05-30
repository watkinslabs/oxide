/* B18 diagnostic: reproduces util-linux login's full post-auth chain
 * (PAM session/setcred → initgroups → setgid → chown_tty → vhangup →
 * TIOCNOTTY → fork → child: setsid → open_tty → TIOCSCTTY → setuid →
 * chdir → pam_end → execvp /bin/sh) and prints a step marker at each
 * call. Used to bisect why util-linux login's post-PAM hand-off
 * fails on the console while the underlying syscalls all work. Run
 * from rcS as root via `/bin/login_sim`. */
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <errno.h>
#include <grp.h>
#include <security/pam_appl.h>

static void w(const char *s) { write(2, s, strlen(s)); }
static void wf(const char *fmt, ...) {
    char b[256]; va_list ap; va_start(ap, fmt);
    int n = vsnprintf(b, sizeof b, fmt, ap); va_end(ap);
    if (n > 0) write(2, b, n);
}

static int conv_fn(int n, const struct pam_message **msg,
                   struct pam_response **resp, void *appdata) {
    const char *pw = appdata;
    struct pam_response *r = calloc(n, sizeof(*r));
    if (!r) return PAM_BUF_ERR;
    for (int i = 0; i < n; i++) {
        r[i].resp = strdup(pw); r[i].resp_retcode = 0;
    }
    *resp = r;
    return PAM_SUCCESS;
}

int main(int argc, char **argv) {
    const char *tty = "/dev/ttyS0";
    const char *user = "alice";
    const char *pw = "swordfish";
    uid_t target_uid = 1000;
    gid_t target_gid = 1000;
    const char *home = "/home/alice";

    wf("[login_sim] start uid=%d\n", (int)getuid());

    struct pam_conv conv = { conv_fn, (void*)pw };
    pam_handle_t *pamh = NULL;
    int rc = pam_start("login", user, &conv, &pamh);
    wf("[login_sim] pam_start rc=%d\n", rc);
    if (rc != PAM_SUCCESS) return 10;
    rc = pam_authenticate(pamh, 0);
    wf("[login_sim] pam_authenticate rc=%d\n", rc);
    if (rc != PAM_SUCCESS) return 11;
    rc = pam_acct_mgmt(pamh, 0);
    wf("[login_sim] pam_acct_mgmt rc=%d\n", rc);
    rc = pam_setcred(pamh, PAM_ESTABLISH_CRED);
    wf("[login_sim] pam_setcred ESTABLISH rc=%d\n", rc);
    rc = pam_open_session(pamh, 0);
    wf("[login_sim] pam_open_session rc=%d\n", rc);
    rc = pam_setcred(pamh, PAM_REINITIALIZE_CRED);
    wf("[login_sim] pam_setcred REINIT rc=%d\n", rc);

    if (initgroups(user, target_gid) < 0) wf("[login_sim] initgroups FAIL errno=%d\n", errno);
    else w("[login_sim] initgroups ok\n");
    if (setgid(target_gid) < 0) { wf("[login_sim] setgid FAIL errno=%d\n", errno); return 20; }
    w("[login_sim] setgid ok\n");
    if (chown(tty, target_uid, target_gid) < 0) wf("[login_sim] chown FAIL errno=%d\n", errno);
    else w("[login_sim] chown ok\n");
    if (chmod(tty, 0620) < 0) wf("[login_sim] chmod FAIL errno=%d\n", errno);
    else w("[login_sim] chmod ok\n");

    signal(SIGHUP, SIG_IGN);
    if (vhangup() < 0) wf("[login_sim] vhangup FAIL errno=%d\n", errno);
    else w("[login_sim] vhangup ok\n");
    signal(SIGHUP, SIG_DFL);

    if (ioctl(0, TIOCNOTTY, NULL) < 0)
        wf("[login_sim] TIOCNOTTY FAIL errno=%d (non-fatal)\n", errno);
    else
        w("[login_sim] TIOCNOTTY ok\n");

    pid_t p = fork();
    if (p < 0) { w("[login_sim] fork FAIL\n"); return 30; }
    if (p > 0) {
        close(0); close(1); close(2);
        int st; waitpid(p, &st, 0);
        return 0;
    }
    if (setsid() < 0) { w("[login_sim] setsid FAIL\n"); _exit(40); }
    int fd = open(tty, O_RDWR);
    if (fd < 0) { w("[login_sim] open tty FAIL\n"); _exit(41); }
    if (!isatty(fd)) { w("[login_sim] isatty FAIL\n"); _exit(42); }
    for (int i = 0; i < fd; i++) close(i);
    if (fd != 0) dup2(fd, 0);
    if (fd != 1) dup2(fd, 1);
    if (fd != 2) dup2(fd, 2);
    if (fd >= 3) close(fd);
    if (ioctl(0, TIOCSCTTY, 1) < 0) w("[login_sim] TIOCSCTTY FAIL\n");
    wf("[login_sim] child pid=%d pgrp=%d sid=%d tcgetpgrp=%d\n",
       (int)getpid(), (int)getpgrp(), (int)getsid(0), (int)tcgetpgrp(0));
    if (setuid(target_uid) < 0) { w("[login_sim] setuid FAIL\n"); _exit(43); }
    if (chdir(home) < 0) w("[login_sim] chdir FAIL\n");
    setenv("HOME", home, 1);
    setenv("USER", user, 1);
    setenv("SHELL", "/bin/sh", 1);
    setenv("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", 1);
    setenv("TERM", "linux", 1);
    pam_end(pamh, PAM_SUCCESS | PAM_DATA_SILENT);
    w("[login_sim] child execvp /bin/sh -sh\n");
    execl("/bin/sh", "-sh", (char*)0);
    w("[login_sim] execvp FAIL\n");
    _exit(44);
}
