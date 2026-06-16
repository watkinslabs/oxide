/* statfs/fstatfs (pass-through) + statvfs/fstatvfs (translated). Diff vs host
 * glibc on a stable mount ("/"). Print derived fields that must match exactly. */
#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>

int main(void) {
    struct statfs sf;
    int r1 = statfs("/", &sf);
    /* f_type/f_bsize are stable identity fields of the root fs */
    printf("statfs=%d nonzero_type=%d bsize=%ld\n",
           r1, sf.f_type != 0, (long)sf.f_bsize);

    int fd = open("/", O_RDONLY);
    struct statfs sf2;
    int r2 = fstatfs(fd, &sf2);
    printf("fstatfs=%d type_match=%d\n", r2, sf.f_type == sf2.f_type);

    struct statvfs vf;
    int r3 = statvfs("/", &vf);
    /* derived mappings glibc guarantees: favail==free count semantics,
     * frsize nonzero, namemax nonzero, flag has no stray ST_VALID(0x20) bit */
    printf("statvfs=%d frsize_nz=%d namemax_nz=%d flag_no_valid=%d\n",
           r3, vf.f_frsize != 0, vf.f_namemax != 0, (vf.f_flag & 0x20) == 0);

    struct statvfs vf2;
    int r4 = fstatvfs(fd, &vf2);
    printf("fstatvfs=%d bsize_match=%d namemax_match=%d\n",
           r4, vf.f_bsize == vf2.f_bsize, vf.f_namemax == vf2.f_namemax);
    close(fd);
    return 0;
}
