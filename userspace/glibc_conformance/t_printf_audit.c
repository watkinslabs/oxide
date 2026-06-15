/* Comprehensive printf conformance audit: the full conversion matrix vs host
   glibc. Any mismatch the harness reports is a real printf bug. */
#include <stdio.h>
#include <math.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>

int main(void){
    /* ---- integers: d/i/u/o/x/X with the flag/width/precision matrix ---- */
    int iv[] = {0, 1, -1, 42, -42, 255, 7, -7, INT_MAX, INT_MIN};
    const char *ifmt[] = {
        "%d","%i","%5d","%-5d","%05d","%+d","% d","%+5d","%-+5d","% 05d",
        "%x","%X","%#x","%#X","%08x","%#010x","%o","%#o","%u",
        "%.0d","%.3d","%5.3d","%-5.3d","%.5x","%#.5x",
    };
    for (size_t f=0; f<sizeof ifmt/sizeof ifmt[0]; f++)
        for (size_t v=0; v<sizeof iv/sizeof iv[0]; v++)
            printf("I|%s|%d=[", ifmt[f], iv[v]), printf(ifmt[f], iv[v]), printf("]\n");
    /* precision 0 with value 0 prints nothing */
    printf("z0=[%.0d][%.0o][%.0x]\n", 0, 0, 0);

    /* ---- length modifiers ---- */
    printf("L|%ld %lld %hhd %hd %zu %ju %td\n",
           -9223372036854775807L-1, 9223372036854775807LL, (signed char)-3,
           (short)-30000, (size_t)18446744073709551615UL, (uintmax_t)123, (ptrdiff_t)-99);
    printf("L|%lx %llx %hhx %hx\n", 0xDEADBEEFL, 0x1122334455667788LL, 0xFF, 0xABCD);

    /* ---- strings & chars ---- */
    printf("S|[%s][%10s][%-10s][%.3s][%10.3s][%-10.3s]\n",
           "hello","hi","hi","truncated","truncated","truncated");
    printf("C|[%c][%5c][%-5c]\n", 'A', 'B', 'C');
    printf("S|null=[%s]\n", (char*)NULL);   /* glibc: (null) */
    printf("P|nil=[%p]\n", (void*)0);       /* glibc: (nil) */

    /* ---- '*' width and precision ---- */
    printf("STAR|[%*d][%-*d][%.*f][%*.*f]\n", 6, 42, 6, 42, 3, 3.14159, 10, 2, 2.5);

    /* ---- positional args ---- */
    printf("POS|%2$d %1$d %3$s %1$d\n", 7, 8, "x");
    printf("POS|%1$.*2$f\n", 3.14159, 4);

    /* ---- floats: f/F/e/E/g/G with flags/precision + special values ---- */
    double dv[] = {0.0, -0.0, 1.0, -1.0, 0.5, 3.14159265358979, 100000.0,
                   0.0001, 1e20, 1e-20, 123456.789, 2.5, 3.5, 0.125};
    const char *ffmt[] = {"%f","%.2f","%10.2f","%-10.2f","%+.2f","%010.2f",
                          "%e","%.3e","%E","%g","%.10g","%G","%#.0f","%.0f"};
    for (size_t f=0; f<sizeof ffmt/sizeof ffmt[0]; f++)
        for (size_t v=0; v<sizeof dv/sizeof dv[0]; v++)
            printf("F|%s|%.4g=[", ffmt[f], dv[v]), printf(ffmt[f], dv[v]), printf("]\n");
    printf("FS|[%f][%e][%g][%.2f]\n", INFINITY, -INFINITY, NAN, NAN);
    printf("FS|[%F][%E][%G]\n", INFINITY, NAN, -INFINITY);

    /* ---- literal %% and adjacent text ---- */
    printf("PCT|100%% done, %d/%d\n", 3, 4);
    return 0;
}
