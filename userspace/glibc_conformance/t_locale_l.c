/* locale object + _l delegators (C locale). Diff vs host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <locale.h>
#include <errno.h>
#define P() fflush(stdout)

int main(void) {
    locale_t loc = newlocale(LC_ALL_MASK, "C", (locale_t)0);
    printf("newlocale=%d\n", loc != (locale_t)0); P();
    locale_t prev = uselocale(loc);
    printf("uselocale_prev_global=%d\n", prev == LC_GLOBAL_LOCALE); P();
    uselocale(LC_GLOBAL_LOCALE); P();
    printf("ctype: %d %d %d %d %d\n",
           isalpha_l('A', loc) != 0, isdigit_l('5', loc) != 0, toupper_l('a', loc) == 'A',
           isspace_l(' ', loc) != 0, ispunct_l('!', loc) != 0); P();
    char *e;
    double d = strtod_l("3.14159", &e, loc); P();
    long n = strtol_l("ff", NULL, 16, loc); P();
    unsigned long u = strtoul_l("123", NULL, 10, loc); P();
    printf("num: %.5f %ld %lu\n", d, n, u); P();
    printf("str: %d %d\n", strcoll_l("a","b",loc) < 0, strcasecmp_l("ABC","abc",loc) == 0); P();
    printf("strerror_l=%s\n", strerror_l(EINVAL, loc)); P();
    freelocale(loc);
    locale_t dup = duplocale(LC_GLOBAL_LOCALE);
    printf("duplocale=%d\n", dup != (locale_t)0); P();
    freelocale(dup);
    return 0;
}
