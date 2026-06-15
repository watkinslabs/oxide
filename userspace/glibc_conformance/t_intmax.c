#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
int main(void){
    char *end;
    const char *s = "-123456789012 tail";
    intmax_t a = strtoimax(s, &end, 10);
    printf("a=%jd consumed=%ld\n", a, (long)(end - s));
    intmax_t b = strtoimax("0x1F", NULL, 0);
    uintmax_t c = strtoumax("18446744073709551615", NULL, 10);
    printf("b=%jd c=%ju\n", b, c);
    intmax_t d = strtoimax("777", NULL, 8);
    printf("d=%jd\n", d);
    return 0;
}
