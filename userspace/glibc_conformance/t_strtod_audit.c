/* strtod/strtof audit vs host glibc. Prints the parsed value round-trip-exact
   (%.17g / %.9g), endptr offset, and errno; any mismatch is a strtod bug. */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

static void D(const char *s){
    char *end; errno = 0;
    double v = strtod(s, &end);
    printf("strtod(%s)=%.17g off=%ld err=%d\n", s, v, (long)(end-s), errno);
}
static void F(const char *s){
    char *end; errno = 0;
    float v = strtof(s, &end);
    printf("strtof(%s)=%.9g off=%ld err=%d\n", s, v, (long)(end-s), errno);
}

int main(void){
    D("0"); D("1"); D("-1"); D("3.14159265358979"); D("0.1"); D("0.2"); D("0.3");
    D("  -2.5e3xyz"); D("+0.0"); D("-0.0"); D("100000000"); D("1e308"); D("1e-308");
    D(".5"); D("5."); D("0.0625"); D("123.456e-2"); D("2.2250738585072014e-308");
    D("1.7976931348623157e308");  /* DBL_MAX */
    D("1e400");                    /* overflow -> inf + ERANGE */
    D("1e-400");                   /* underflow -> 0 + ERANGE */
    D("inf"); D("INFINITY"); D("-inf"); D("nan"); D("NAN");
    D("0x1.8p3");                  /* hex float = 12 */
    D("0x1p-4");                   /* = 0.0625 */
    D("0x10");                     /* = 16 */
    D("abc"); D(""); D("   ");
    D("1.5e+10"); D("9.999999999999999e22"); D("4503599627370497");
    F("3.14159"); F("1e38"); F("1e-38"); F("0.1"); F("1e40"); F("16777217");
    return 0;
}
