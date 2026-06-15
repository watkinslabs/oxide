#include <stdio.h>
#include <time.h>
int main(void){
    time_t t = 533254968; /* 1986-11-24 18:22:48 UTC */
    char buf[64];
    struct tm g; gmtime_r(&t, &g);
    printf("asctime=%s", asctime(&g));   /* includes trailing \n */
    asctime_r(&g, buf);
    printf("asctime_r=%s", buf);
    /* ctime/ctime_r are local-time (TZ-dependent) — not differentially
       tested here since the harness does not pin TZ. */
    printf("difftime=%.1f\n", difftime(t + 3600, t));
    printf("difftime_neg=%.1f\n", difftime(t, t + 90));
    return 0;
}
