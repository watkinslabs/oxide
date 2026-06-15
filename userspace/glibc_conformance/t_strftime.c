#include <stdio.h>
#include <time.h>
int main(void){
    time_t t = 1700000000; struct tm g; gmtime_r(&t, &g);
    char b[128];
    strftime(b, sizeof b, "%A %B %d %Y", &g); printf("1=%s\n", b);
    strftime(b, sizeof b, "%a %b %j %p %I:%M", &g); printf("2=%s\n", b);
    strftime(b, sizeof b, "%H:%M:%S %Z %%", &g); printf("3=%s\n", b);
    return 0;
}
