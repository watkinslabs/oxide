// /bin/sysblock_probe — /sys/block sysfs tree regression (drivers-plan D7a).
//
// lsblk / udev / systemd's find-root read /sys/block to enumerate disks and
// their geometry. Proves the dynamic /sys/block tree reflects the live block
// registry: the root disk (vda) appears, its `size` is a nonzero count of
// 512-byte sectors (the classic Linux units gotcha — always 512-byte units
// regardless of logical block size), and queue/logical_block_size reports
// 512. Also confirms at least one disk dir is enumerable via opendir.

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <stdio.h>
#include <sys/stat.h>

static void emit(const char *m) { write(1, m, strlen(m)); }

// Read a small sysfs attr into buf (NUL-terminated). Returns bytes read, or
// -1 on open/read failure.
static long read_attr(const char *path, char *buf, long cap) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    long n = (long)read(fd, buf, (size_t)(cap - 1));
    close(fd);
    if (n < 0) return -1;
    buf[n] = '\0';
    return n;
}

static void trim_lf(char *s) {
    char *p = strchr(s, '\n');
    if (p) *p = '\0';
}

static int dir_has(const char *path, const char *name) {
    DIR *d = opendir(path);
    if (!d) return 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, name)) {
            closedir(d);
            return 1;
        }
    }
    closedir(d);
    return 0;
}

static int check_dev_index(const char *kind, const char *dev,
                           const char *target, const char *tag) {
    char path[128], attr[160], link[160], buf[64];
    struct stat st;
    snprintf(path, sizeof path, "/sys/dev/%s/%s", kind, dev);
    if (lstat(path, &st) < 0 || !S_ISLNK(st.st_mode)) {
        printf("%s: FAIL missing-symlink path=%s\n", tag, path);
        return 1;
    }
    ssize_t n = readlink(path, link, sizeof link - 1);
    if (n < 0) {
        printf("%s: FAIL readlink path=%s\n", tag, path);
        return 1;
    }
    link[n] = '\0';
    if (target[0] == '*' ? !strstr(link, target + 1) : strcmp(link, target)) {
        printf("%s: FAIL target=%s expected=%s\n", tag, link, target);
        return 1;
    }
    snprintf(attr, sizeof attr, "%s/dev", path);
    if (read_attr(attr, buf, sizeof buf) < 0) {
        printf("%s: FAIL resolved-dev path=%s\n", tag, attr);
        return 1;
    }
    trim_lf(buf);
    if (strcmp(buf, dev)) {
        printf("%s: FAIL resolved-dev=%s expected=%s\n", tag, buf, dev);
        return 1;
    }
    if (!dir_has(kind[0] == 'b' ? "/sys/dev/block" : "/sys/dev/char", dev)) {
        printf("%s: FAIL readdir-missing dev=%s\n", tag, dev);
        return 1;
    }
    printf("%s: PASS dev=%s target=%s\n", tag, dev, target);
    return 0;
}

int main(void) {
    char buf[64];

    // /sys/block/vda/size — capacity in 512-byte sectors, must be > 0.
    if (read_attr("/sys/block/vda/size", buf, sizeof buf) < 0) {
        emit("sysblock_probe: FAIL open size\n"); return 1;
    }
    long vda_size = atol(buf);
    if (vda_size <= 0) { emit("sysblock_probe: FAIL size==0\n"); return 1; }

    // queue/logical_block_size must be 512.
    if (read_attr("/sys/block/vda/queue/logical_block_size", buf, sizeof buf) < 0) {
        emit("sysblock_probe: FAIL open logical_block_size\n"); return 1;
    }
    if (atol(buf) != 512) {
        emit("sysblock_probe: FAIL logical_block_size!=512\n"); return 1;
    }

    // ro must report read-write ("0").
    if (read_attr("/sys/block/vda/ro", buf, sizeof buf) < 0 || buf[0] != '0') {
        emit("sysblock_probe: FAIL ro\n"); return 1;
    }

    // dev must be "<major>:<minor>" — non-empty with a colon.
    if (read_attr("/sys/block/vda/dev", buf, sizeof buf) < 0 || !strchr(buf, ':')) {
        emit("sysblock_probe: FAIL dev\n"); return 1;
    }
    trim_lf(buf);
    char vda_dev[64];
    snprintf(vda_dev, sizeof vda_dev, "%s", buf);

    // At least one disk dir is enumerable via opendir(/sys/block).
    DIR *d = opendir("/sys/block");
    if (!d) { emit("sysblock_probe: FAIL opendir\n"); return 1; }
    int ndisks = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        ndisks++;
    }
    closedir(d);
    if (ndisks < 1) { emit("sysblock_probe: FAIL no disks\n"); return 1; }

    if (check_dev_index("block", vda_dev, "../../devices/virtual/block/vda",
                        "b588_sys_dev_block_vda")) return 1;
    if (check_dev_index("char", "1:3", "../../devices/virtual/mem/null",
                        "b588_sys_dev_char_null")) return 1;
    if (check_dev_index("char", "226:0", "*/drm/card0",
                        "b588_sys_dev_char_drm_card0")) return 1;

    char out[64]; int p = 0;
    const char *pre = "sysblock_probe: PASS vda_size=";
    memcpy(out, pre, strlen(pre)); p = (int)strlen(pre);
    char tmp[24]; int n = 0; long v = vda_size;
    if (v == 0) tmp[n++] = '0';
    while (v) { tmp[n++] = (char)('0' + v % 10); v /= 10; }
    while (n) out[p++] = tmp[--n];
    out[p++] = '\n'; out[p] = '\0';
    emit(out);
    return 0;
}
