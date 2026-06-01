// /bin/symlink_probe — K2V V6 regression guard: stat(2) now resolves
// through the dentry path-walk (vfs::path_lookup) as THE resolver —
// crossing mounts and following symlinks. Verifies, in one process:
//   * ext4 symlink follow: lstat(/sl_link)=link, stat=followed regular,
//     readlink=target (fixture baked into the image — ext4 symlink
//     CREATE isn't implemented).
//   * mount-crossing via the walker: stat(/dev/null)=char dev,
//     stat(/proc/version)=regular (whole-path delegation into procfs),
//     stat(/sys)=dir.

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#define PASS "symlink_probe: PASS\n"
static int fail(const char *why) {
    char b[96]; int n = snprintf(b, sizeof b, "symlink_probe: FAIL %s errno=%d\n", why, errno);
    write(1, b, n);
    return 1;
}

int main(void) {
    struct stat st, lst;

    // ext4 symlink: lstat keeps the link, stat follows to the target.
    if (lstat("/sl_link", &lst) < 0) return fail("lstat");
    if (!S_ISLNK(lst.st_mode)) return fail("lstat-not-link");
    if (stat("/sl_link", &st) < 0) return fail("stat-link");
    if (!S_ISREG(st.st_mode)) return fail("stat-did-not-follow");
    if (st.st_size != 4) return fail("followed-size");
    char tgt[64];
    int tn = readlink("/sl_link", tgt, sizeof tgt - 1);
    if (tn < 0) return fail("readlink");
    tgt[tn] = '\0';
    if (strcmp(tgt, "/sl_target") != 0) return fail("readlink-target");

    // Mount-crossing via the walker.
    if (stat("/dev/null", &st) < 0) return fail("stat-dev-null");
    if (!S_ISCHR(st.st_mode)) return fail("dev-null-not-chr");
    if (stat("/proc/version", &st) < 0) return fail("stat-proc-version");
    if (!S_ISREG(st.st_mode)) return fail("proc-version-not-reg");
    if (stat("/sys", &st) < 0) return fail("stat-sys");
    if (!S_ISDIR(st.st_mode)) return fail("sys-not-dir");

    // open() follows the symlink → reads the target's bytes (V6c).
    char buf[8];
    int rfd = open("/sl_link", O_RDONLY);
    if (rfd < 0) return fail("open-link");
    int n = read(rfd, buf, sizeof buf);
    close(rfd);
    if (n != 4 || memcmp(buf, "SLOK", 4) != 0) return fail("read-through-link");

    write(1, PASS, sizeof(PASS) - 1);
    return 0;
}
