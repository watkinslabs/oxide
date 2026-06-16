/* sched_getattr/sched_setattr/sched_getcpu vs host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sched.h>
#include <unistd.h>
#include <linux/sched/types.h>
int main(void){
    struct sched_attr { unsigned size, sched_policy; unsigned long long sched_flags;
        int sched_nice; unsigned sched_priority;
        unsigned long long sched_runtime, sched_deadline, sched_period; } a;
    memset(&a,0,sizeof a); a.size=sizeof a;
    int r = sched_getattr(0, (void*)&a, sizeof a, 0);
    printf("getattr=%d policy=%u nice=%d prio=%u\n", r, a.sched_policy, a.sched_nice, a.sched_priority);
    /* set nice to 5 under SCHED_OTHER, then read back */
    struct sched_attr s; memset(&s,0,sizeof s); s.size=sizeof s;
    s.sched_policy=0; s.sched_nice=5;
    int sr = sched_setattr(0,(void*)&s,0);
    memset(&a,0,sizeof a); a.size=sizeof a;
    sched_getattr(0,(void*)&a,sizeof a,0);
    printf("setattr=%d nice_after=%d\n", sr, a.sched_nice);
    /* getcpu valid range */
    int c = sched_getcpu();
    printf("getcpu_valid=%d\n", c>=0);
    /* bad: size too small -> -1 */
    char tiny[4];
    printf("getattr_tiny=%d\n", sched_getattr(0,(void*)tiny,4,0));
    return 0;
}
