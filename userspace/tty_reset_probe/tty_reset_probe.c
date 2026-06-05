// BUG E triage: systemd logs "Failed to reset TTY ownership/access mode of
// /dev/console to 0:5, ignoring: Invalid argument". oxide's fchmod(fd)/
// fchown(fd) return 0, so the EINVAL must be a different call in systemd's
// reset path. Mimic every candidate on /dev/console and report each errno so
// we know exactly which one oxide rejects.
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

static int w(const char *s){ return write(1,(s),strlen(s)); }
static void rep(const char *tag, int rc){
    char b[96];
    snprintf(b,sizeof b,"  %-22s rc=%d errno=%d\n", tag, rc, rc<0?errno:0);
    w(b);
}

int main(void){
    w("tty_reset_probe: start\n");
    int fd = open("/dev/console", O_RDWR|O_NOCTTY);
    if (fd < 0){ rep("open(/dev/console)", fd); fd = 1; w("  (falling back to fd 1)\n"); }

    errno=0; rep("fchmod(fd,0620)",            fchmod(fd, 0620));
    errno=0; rep("fchown(fd,0,5)",             fchown(fd, 0, 5));
    // systemd may use the *at forms with AT_EMPTY_PATH on the fd:
    errno=0; rep("fchmodat(fd,\"\",AT_EMPTY)", fchmodat(fd, "", 0620, AT_EMPTY_PATH));
    errno=0; rep("fchownat(fd,\"\",AT_EMPTY)", fchownat(fd, "", 0, 5, AT_EMPTY_PATH));
    // …or by path:
    errno=0; rep("chmod(/dev/console)",        chmod("/dev/console", 0620));
    errno=0; rep("chown(/dev/console,0,5)",    chown("/dev/console", 0, 5));
    // fstat sanity (does the fd resolve at all?)
    struct stat st; errno=0; int sr=fstat(fd,&st);
    rep("fstat(fd)", sr);
    w("tty_reset_probe: done\n");
    return 0;
}
