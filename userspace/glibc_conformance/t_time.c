#include <stdio.h>
#include <time.h>
int main(void){
    time_t t = 1700000000; /* fixed epoch */
    struct tm g; gmtime_r(&t, &g);
    char buf[64]; strftime(buf, sizeof buf, "%Y-%m-%d %H:%M:%S", &g);
    printf("gm=%s wday=%d yday=%d\n", buf, g.tm_wday, g.tm_yday);
    struct tm c = g; time_t back = timegm(&c);
    printf("roundtrip=%d\n", (int)(back == t));
    return 0;
}
