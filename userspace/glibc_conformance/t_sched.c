/* sched + resource wrappers vs host glibc. Same host kernel for both, so
 * syscall results match. Print booleans / fixed relationships, never
 * environment-specific absolute values, for byte-identical output. */
#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
#include <sys/resource.h>
#include <string.h>

int main(void){
    /* scheduler policy of self (default is SCHED_OTHER==0) */
    printf("getscheduler==OTHER=%d\n", sched_getscheduler(0) == SCHED_OTHER);

    /* priority ranges are policy-fixed Linux contract values */
    printf("fifo_max=%d fifo_min=%d\n",
           sched_get_priority_max(SCHED_FIFO),
           sched_get_priority_min(SCHED_FIFO));
    printf("other_max=%d other_min=%d\n",
           sched_get_priority_max(SCHED_OTHER),
           sched_get_priority_min(SCHED_OTHER));

    /* getparam: SCHED_OTHER tasks have priority 0 */
    struct sched_param sp; memset(&sp, 0, sizeof sp);
    int gp = sched_getparam(0, &sp);
    printf("getparam=%d prio0=%d\n", gp == 0, sp.sched_priority == 0);

    /* nice value of self via getpriority */
    int pr = getpriority(PRIO_PROCESS, 0);
    printf("getprio_in_range=%d\n", pr >= -20 && pr <= 19);

    /* rlimit: call succeeds and the invariant rlim_cur<=rlim_max holds */
    struct rlimit r;
    int gr = getrlimit(RLIMIT_NOFILE, &r);
    printf("getrlimit=%d cur_le_max=%d\n", gr == 0, r.rlim_cur <= r.rlim_max);

    /* two reads of the same limit must agree */
    struct rlimit r2;
    getrlimit(RLIMIT_NOFILE, &r2);
    printf("rlimit_stable=%d\n", r.rlim_cur == r2.rlim_cur && r.rlim_max == r2.rlim_max);

    /* affinity: at least one CPU in the mask. Popcount the raw bytes by
     * hand (CPU_COUNT pulls in the glibc-internal __sched_cpucount). */
    cpu_set_t set; CPU_ZERO(&set);
    int ga = sched_getaffinity(0, sizeof set, &set);
    const unsigned char *mb = (const unsigned char *)&set;
    int nbits = 0;
    for (size_t i = 0; i < sizeof set; i++) { unsigned char b = mb[i]; while (b) { nbits += b & 1; b >>= 1; } }
    printf("getaffinity=%d ncpu_pos=%d\n", ga == 0, nbits > 0);

    /* rusage: call succeeds, maxrss is non-negative */
    struct rusage ru; memset(&ru, 0, sizeof ru);
    int gu = getrusage(RUSAGE_SELF, &ru);
    printf("getrusage=%d maxrss_ge0=%d\n", gu == 0, ru.ru_maxrss >= 0);

    /* sched_yield always succeeds */
    printf("yield=%d\n", sched_yield() == 0);
    return 0;
}
