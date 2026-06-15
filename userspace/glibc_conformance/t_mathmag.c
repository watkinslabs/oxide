/* t_mathmag — fmaxmag/fminmag (C23) + gammaf (lgammaf alias) + strfmon
 * monetary formatting + pthread default-attr (GNU np). Differentially diffed
 * against host glibc by xtask glibc-test (C locale, byte-identical). */
#define _GNU_SOURCE
#include <stdio.h>
#include <math.h>
#include <monetary.h>
#include <pthread.h>
#include <locale.h>

int main(void) {
    setlocale(LC_ALL, "C");

    /* ---- math magnitude ---- */
    printf("fmaxmag(2,-3)=%.1f fminmag(2,-3)=%.1f\n", fmaxmag(2.0, -3.0), fminmag(2.0, -3.0));
    printf("fmaxmag(-5,5)=%.1f fminmag(-5,5)=%.1f\n", fmaxmag(-5.0, 5.0), fminmag(-5.0, 5.0));
    printf("fmaxmag(nan,1)=%.1f fminmag(nan,1)=%.1f\n", fmaxmag(NAN, 1.0), fminmag(NAN, 1.0));
    printf("fmaxmagf(2,-3)=%.1f fminmagf(2,-3)=%.1f\n", fmaxmagf(2.0f, -3.0f), fminmagf(2.0f, -3.0f));

    /* ---- gammaf (== lgammaf, log-gamma) ---- */
    printf("gammaf(0.5)=%.13g gammaf(1)=%.13g gammaf(5)=%.13g\n",
           (double)gammaf(0.5f), (double)gammaf(1.0f), (double)gammaf(5.0f));

    /* ---- strfmon ---- */
    char b[128];
    strfmon(b, sizeof b, "%n", 1234.567);   printf("strfmon %%n   ='%s'\n", b);
    strfmon(b, sizeof b, "%i", 1234.567);   printf("strfmon %%i   ='%s'\n", b);
    strfmon(b, sizeof b, "%.2n", 1234.567); printf("strfmon %%.2n ='%s'\n", b);
    strfmon(b, sizeof b, "%#6n", 1234.567); printf("strfmon %%#6n ='%s'\n", b);
    strfmon(b, sizeof b, "%n", -1234.567);  printf("strfmon neg  ='%s'\n", b);
    strfmon(b, sizeof b, "%(n", -1234.567); printf("strfmon (neg ='%s'\n", b);
    strfmon(b, sizeof b, "%11.2n", -5.5);   printf("strfmon w11  ='%s'\n", b);
    strfmon(b, sizeof b, "%-11.2n", -5.5);  printf("strfmon left ='%s'\n", b);

    /* ---- pthread default attr ---- */
    pthread_attr_t a;
    size_t gs = 0;
    pthread_getattr_default_np(&a);
    pthread_attr_getguardsize(&a, &gs);
    printf("default guardsize=%zu\n", (size_t)gs);

    pthread_attr_t nb;
    pthread_attr_init(&nb);
    pthread_attr_setguardsize(&nb, 8192);
    pthread_setattr_default_np(&nb);
    pthread_attr_t a2;
    size_t gs2 = 0;
    pthread_getattr_default_np(&a2);
    pthread_attr_getguardsize(&a2, &gs2);
    printf("set guardsize=%zu\n", (size_t)gs2);
    return 0;
}
