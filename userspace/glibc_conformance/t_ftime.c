/* ftime legacy wall-clock wrapper properties vs host glibc. */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <sys/timeb.h>
#include <time.h>

int main(void){
    struct timeb tb;
    int r = ftime(&tb);
    time_t now = time(NULL);
    printf("layout=%zu/%zu/%zu/%zu/%zu\n",
           sizeof tb, offsetof(struct timeb,time), offsetof(struct timeb,millitm),
           offsetof(struct timeb,timezone), offsetof(struct timeb,dstflag));
    printf("r=%d ms_range=%d tz=%d dst=%d delta_ok=%d\n",
           r, tb.millitm < 1000, tb.timezone, tb.dstflag,
           tb.time >= now - 2 && tb.time <= now + 2);
    return 0;
}
