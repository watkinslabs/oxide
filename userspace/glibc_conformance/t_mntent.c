/* mntent vs host glibc — parse a fake fstab via fmemopen (no real /etc files). */
#define _GNU_SOURCE
#include <stdio.h>
#include <mntent.h>
#include <string.h>

int main(void){
    char fstab[] =
        "# a comment line\n"
        "\n"
        "/dev/sda1 / ext4 rw,relatime 0 1\n"
        "proc /proc proc defaults 0 0\n"
        "tmpfs /tmp tmpfs rw,nosuid,size=2G\n"; /* short: no freq/passno */
    FILE *f = fmemopen(fstab, strlen(fstab), "r");
    struct mntent *m;
    while ((m = getmntent(f))) {
        printf("[%s|%s|%s|%s|%d|%d]\n", m->mnt_fsname, m->mnt_dir, m->mnt_type,
               m->mnt_opts, m->mnt_freq, m->mnt_passno);
        printf("  has_rw=%d has_size=%d has_nope=%d\n",
               hasmntopt(m, "rw") != NULL, hasmntopt(m, "size") != NULL, hasmntopt(m, "nope") != NULL);
    }
    endmntent(f);
    return 0;
}
