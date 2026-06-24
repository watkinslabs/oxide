#define _GNU_SOURCE
#include <locale.h>
#include <stdio.h>
#include <time.h>
#include <wchar.h>
int main(void){
    time_t t = 1700000000; struct tm g; gmtime_r(&t, &g);
    char b[128];
    strftime(b, sizeof b, "%A %B %d %Y", &g); printf("1=%s\n", b);
    strftime(b, sizeof b, "%a %b %j %p %I:%M", &g); printf("2=%s\n", b);
    strftime(b, sizeof b, "%H:%M:%S %Z %%", &g); printf("3=%s\n", b);
    locale_t loc = newlocale(LC_ALL_MASK, "C", (locale_t)0);
    strftime_l(b, sizeof b, "%F %T %a", &g, loc); printf("l1=%s\n", b);
    struct tm p = {0};
    char *end = strptime_l("2023-07-09 04:05:06!", "%F %T", &p, loc);
    printf("pl=%ld y=%d m=%d d=%d h=%d m=%d s=%d\n",
           end ? (long)(end - "2023-07-09 04:05:06!") : -1L,
           p.tm_year, p.tm_mon, p.tm_mday, p.tm_hour, p.tm_min, p.tm_sec);
    wchar_t wb[128];
    size_t wn = wcsftime_l(wb, 128, L"%Y/%m/%d %H:%M", &g, loc);
    printf("wl=%zu %ls\n", wn, wb);
    freelocale(loc);
    return 0;
}
