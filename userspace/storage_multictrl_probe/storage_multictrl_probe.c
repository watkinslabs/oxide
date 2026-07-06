// /bin/storage_multictrl_probe — NVMe/AHCI multi-controller sysfs rebind proof.
// Proves two NVMe disks and two AHCI disks exist, then unbinds/rebinds one
// PCI controller of each driver and checks /sys/block returns to its count.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

#define MAX_DEVS 8
#define MAX_NAME 64
#define MAX_PATH 160
#define RETRIES 50
#define SLEEP_US 100000

static void emit_line(const char *msg) {
    write(1, msg, strlen(msg));
    int fd = open("/dev/kmsg", O_WRONLY);
    if (fd >= 0) {
        write(fd, msg, strlen(msg));
        close(fd);
    }
}

static void mount_api_fs(void) {
    mount("proc", "/proc", "proc", 0, "");
    mount("sysfs", "/sys", "sysfs", 0, "");
    mount("tmpfs", "/tmp", "tmpfs", 0, "");
    mount("devpts", "/dev/pts", "devpts", 0, "");
}

static int count_block_prefix(const char *prefix) {
    DIR *d = opendir("/sys/block");
    if (!d) return -1;
    int n = 0;
    size_t len = strlen(prefix);
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (!strncmp(e->d_name, prefix, len)) n++;
    }
    closedir(d);
    return n;
}

static int block_name_exists(const char *name) {
    char path[MAX_PATH];
    snprintf(path, sizeof path, "/sys/block/%s", name);
    int fd = open(path, O_RDONLY | O_DIRECTORY);
    if (fd < 0) return 0;
    close(fd);
    return 1;
}

static int require_block_name(const char *name, const char *tag) {
    if (!block_name_exists(name)) {
        printf("%s: FAIL missing /sys/block/%s\n", tag, name);
        return 1;
    }
    printf("%s: PASS /sys/block/%s\n", tag, name);
    return 0;
}

static int wait_count(const char *prefix, int want) {
    for (int i = 0; i < RETRIES; i++) {
        if (count_block_prefix(prefix) == want) return 0;
        usleep(SLEEP_US);
    }
    return 1;
}

static int list_bound(const char *driver, char names[MAX_DEVS][MAX_NAME]) {
    DIR *d = opendir(driver);
    if (!d) { printf("storage_multictrl_probe: FAIL opendir %s errno=%d\n", driver, errno); return -1; }
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        if (!strcmp(e->d_name, "bind") || !strcmp(e->d_name, "unbind")) continue;
        if (n < MAX_DEVS) {
            strncpy(names[n], e->d_name, MAX_NAME - 1);
            names[n][MAX_NAME - 1] = '\0';
        }
        n++;
    }
    closedir(d);
    return n;
}

static int device_bound(const char *driver, const char *name) {
    char names[MAX_DEVS][MAX_NAME];
    int n = list_bound(driver, names);
    if (n < 0) return 0;
    for (int i = 0; i < n && i < MAX_DEVS; i++) {
        if (!strcmp(names[i], name)) return 1;
    }
    return 0;
}

static int write_token(const char *driver, const char *leaf, const char *token, const char *tag) {
    char path[MAX_PATH];
    snprintf(path, sizeof path, "%s/%s", driver, leaf);
    int fd = open(path, O_WRONLY);
    if (fd < 0) { printf("%s: FAIL open errno=%d\n", tag, errno); return 1; }
    ssize_t n = write(fd, token, strlen(token));
    int saved = errno;
    close(fd);
    if (n != (ssize_t)strlen(token)) {
        printf("%s: FAIL write n=%ld errno=%d token=%s\n", tag, (long)n, saved, token);
        return 1;
    }
    printf("%s: PASS\n", tag);
    return 0;
}

static int write_token_fails(const char *driver, const char *leaf, const char *token, const char *tag) {
    char path[MAX_PATH];
    snprintf(path, sizeof path, "%s/%s", driver, leaf);
    int fd = open(path, O_WRONLY);
    if (fd < 0) { printf("%s: FAIL open errno=%d\n", tag, errno); return 1; }
    ssize_t n = write(fd, token, strlen(token));
    int saved = errno;
    close(fd);
    if (n >= 0) {
        printf("%s: FAIL write unexpectedly succeeded n=%ld token=%s\n", tag, (long)n, token);
        return 1;
    }
    printf("%s: PASS errno=%d\n", tag, saved);
    return 0;
}

static int require_count(const char *prefix, int want, const char *tag) {
    int got = count_block_prefix(prefix);
    if (got < want) {
        printf("%s: FAIL count=%d want=%d\n", tag, got, want);
        return 1;
    }
    printf("%s: PASS count=%d\n", tag, got);
    return 0;
}

static int exercise(const char *name, const char *driver, const char *prefix) {
    char names[MAX_DEVS][MAX_NAME];
    int n = list_bound(driver, names);
    printf("storage_multictrl_probe: %s bound:", name);
    for (int i = 0; i < n && i < MAX_DEVS; i++) printf(" %s", names[i]);
    printf("\n");
    if (n < 2) { printf("storage_multictrl_probe: FAIL %s bound count=%d\n", name, n); return 1; }

    const char *dev = names[0];
    int before = count_block_prefix(prefix);
    printf("storage_multictrl_probe: %s selected addr=%s before=%d\n", name, dev, before);
    char tag[MAX_NAME];
    snprintf(tag, sizeof tag, "storage_%s_duplicate_bind", name);
    if (write_token_fails(driver, "bind", dev, tag)) return 1;
    if (!device_bound(driver, dev)) { printf("storage_multictrl_probe: FAIL %s duplicate unbound\n", name); return 1; }
    if (count_block_prefix(prefix) != before) {
        printf("storage_multictrl_probe: FAIL %s duplicate count=%d want=%d\n",
               name, count_block_prefix(prefix), before);
        return 1;
    }
    printf("storage_multictrl_probe: PASS %s duplicate rejected count=%d\n", name, before);

    snprintf(tag, sizeof tag, "storage_%s_unbind_write", name);
    if (write_token(driver, "unbind", dev, tag)) return 1;
    if (device_bound(driver, dev)) { printf("storage_multictrl_probe: FAIL %s still bound\n", name); return 1; }
    if (wait_count(prefix, before - 1)) {
        printf("storage_multictrl_probe: FAIL %s unbind count=%d want=%d\n",
               name, count_block_prefix(prefix), before - 1);
        return 1;
    }
    printf("storage_multictrl_probe: PASS %s unbind count=%d\n", name, before - 1);

    snprintf(tag, sizeof tag, "storage_%s_bind_write", name);
    if (write_token(driver, "bind", dev, tag)) return 1;
    if (!device_bound(driver, dev)) { printf("storage_multictrl_probe: FAIL %s not rebound\n", name); return 1; }
    if (wait_count(prefix, before)) {
        printf("storage_multictrl_probe: FAIL %s rebind count=%d want=%d\n",
               name, count_block_prefix(prefix), before);
        return 1;
    }
    printf("storage_multictrl_probe: PASS %s rebind count=%d\n", name, before);
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    emit_line("storage_multictrl_probe: START\n");
    mount_api_fs();
    if (require_count("nvme", 2, "storage_nvme_initial") ||
        require_block_name("nvme0n1", "storage_nvme0n1_initial") ||
        require_block_name("nvme1n1", "storage_nvme1n1_initial") ||
        require_count("sd", 2, "storage_ahci_initial") ||
        require_block_name("sda", "storage_sda_initial") ||
        require_block_name("sdb", "storage_sdb_initial")) return 1;
    if (exercise("nvme", "/sys/bus/pci/drivers/nvme", "nvme") ||
        exercise("ahci", "/sys/bus/pci/drivers/ahci", "sd")) return 1;
    emit_line("driver_path_smoke: PASS - storage-multictrl-rebind\n");
    return 0;
}
