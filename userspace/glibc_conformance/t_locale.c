#include <stdio.h>
#include <locale.h>
int main(void){
    char *l = setlocale(LC_ALL, "C"); printf("set=%s\n", l?l:"null");
    struct lconv *lc = localeconv();
    printf("dp=[%s] ts=[%s] fd=%d\n", lc->decimal_point, lc->thousands_sep, lc->frac_digits);
    return 0;
}
