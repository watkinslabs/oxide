/* uname / sysconf / getpagesize / get_nprocs / getitimer / getgroups /
 * clock / times vs host glibc. Prints fixed values + booleans only (no
 * volatile counts), so our libc and the host kernel agree byte-for-byte. */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/times.h>
#include <time.h>
#include <grp.h>

int main(void){
    struct utsname u;
    int ur = uname(&u);
    printf("uname=%d sysname=%s\n", ur, u.sysname);

    printf("pagesize=%ld getpagesize=%d\n",
           sysconf(_SC_PAGESIZE), getpagesize());
    printf("clk_tck=%ld\n", sysconf(_SC_CLK_TCK));
    printf("open_max>0=%d\n", sysconf(_SC_OPEN_MAX) > 0);
    printf("ngroups_max>0=%d\n", sysconf(_SC_NGROUPS_MAX) > 0);
    printf("nprocs>0=%d\n", get_nprocs() > 0);
    printf("nprocs_conf>0=%d\n", get_nprocs_conf() > 0);
    printf("phys_pages>0=%d\n", get_phys_pages() > 0);

    struct itimerval it;
    printf("getitimer=%d\n", getitimer(ITIMER_REAL, &it));

    printf("getgroups>=0=%d\n", getgroups(0, NULL) >= 0);

    printf("clock>=0=%d\n", clock() >= 0);

    struct tms tb;
    printf("times!=-1=%d\n", times(&tb) != (clock_t)-1);

    return 0;
}
