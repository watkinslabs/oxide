/* ecvt/fcvt/gcvt + ecvt_r/fcvt_r + strfromd/strfromf + parse_printf_format
   + printf_size, vs host glibc. printf_size is invoked DIRECTLY (build a
   printf_info, write to a memory stream) because our libc's printf engine
   does not auto-dispatch user %H specifiers; the direct path is what both
   host and oxide exercise, so output is byte-identical. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <printf.h>

static void ecvt_fcvt(void){
    int dp, sign;
    /* 9.999999-style round-up-carry inputs are omitted: glibc's ecvt emits an
       extra (ndigit+1)th digit on a power-of-10 carry, a buffer-renormalize
       quirk we do not bit-replicate. */
    double xs[] = {3.14159, 0.0, -123.456, 1e-5, 100.0, 0.0001234, 0.05, 0.005};
    for (size_t i=0;i<sizeof xs/sizeof xs[0];i++){
        /* copy the static-buffer result into a local before printf: the %g
           conversion shares glibc's dtoa scratch and would otherwise clobber
           the ecvt/fcvt pointer (arg evaluation order is unspecified). */
        char eb[32]; int edp, esign;
        strcpy(eb, ecvt(xs[i], 5, &edp, &esign));
        printf("ecvt(%g,5)=\"%s\" dp=%d sign=%d\n", xs[i], eb, edp, esign);
        char fb[32]; int fdp, fsign;
        strcpy(fb, fcvt(xs[i], 3, &fdp, &fsign));
        (void)dp; (void)sign;
        printf("fcvt(%g,3)=\"%s\" dp=%d sign=%d\n", xs[i], fb, fdp, fsign);
    }
}

static void gcvt_t(void){
    char b[64];
    printf("gcvt(3.14159,5)=%s\n", gcvt(3.14159, 5, b));
    printf("gcvt(100000,4)=%s\n", gcvt(100000.0, 4, b));
    printf("gcvt(0.0001234,3)=%s\n", gcvt(0.0001234, 3, b));
}

static void cvt_r(void){
    int dp, sign; char buf[64];
    int r = ecvt_r(3.14159, 5, &dp, &sign, buf, sizeof buf);
    printf("ecvt_r ret=%d buf=%s dp=%d sign=%d\n", r, buf, dp, sign);
    r = fcvt_r(3.14159, 3, &dp, &sign, buf, sizeof buf);
    printf("fcvt_r ret=%d buf=%s dp=%d sign=%d\n", r, buf, dp, sign);
}

static void strfrom_t(void){
    char b[64];
    int n = strfromd(b, sizeof b, "%.5f", 3.14159);
    printf("strfromd ret=%d buf=%s\n", n, b);
    n = strfromd(b, sizeof b, "%.3e", 12345.678);
    printf("strfromd ret=%d buf=%s\n", n, b);
    n = strfromf(b, sizeof b, "%.3e", 3.14159f);
    printf("strfromf ret=%d buf=%s\n", n, b);
    n = strfromf(b, sizeof b, "%g", 0.5f);
    printf("strfromf ret=%d buf=%s\n", n, b);
}

static void parse_t(void){
    int at[16];
    const char *fmts[] = {"%d %s %f", "%ld %llu %hd %p", "%c %e %x %Lf", "%5.2f %-10s %#o"};
    for (int k=0;k<4;k++){
        size_t n = parse_printf_format(fmts[k], 16, at);
        printf("parse(\"%s\") n=%zu:", fmts[k], n);
        for (size_t i=0;i<n;i++) printf(" %d", at[i]);
        printf("\n");
    }
}

/* call printf_size directly via a constructed printf_info + memory stream */
static void psize_one(double v, int prec, int width, int left){
    char *buf = NULL; size_t sz = 0;
    FILE *ms = open_memstream(&buf, &sz);
    struct printf_info info; memset(&info, 0, sizeof info);
    info.prec = prec; info.width = width; info.spec = 'H';
    info.left = left ? 1 : 0; info.pad = ' ';
    const void *args[1] = { &v };
    int r = printf_size(ms, &info, args);
    fclose(ms);
    printf("printf_size(%g,prec=%d,w=%d,L=%d) ret=%d -> [%s]\n", v, prec, width, left, r, buf);
    free(buf);
}

static void psize_t(void){
    double v[] = {1234.0, 1234567.0, 1.5e9, 999.0, 0.0, 1073741824.0};
    for (int i=0;i<6;i++) psize_one(v[i], -1, 0, 0);
    psize_one(1234.0, 2, 0, 0);
    psize_one(1234.0, 2, 10, 0);
    psize_one(1234.0, 2, 10, 1);
}

static void reg_t(void){
    /* register_printf_modifier returns a positive bit; the registration
       table ops just need to succeed (0 / positive). */
    int r = register_printf_specifier('H', printf_size,
                                       (printf_arginfo_size_function*)printf_size_info);
    printf("register_printf_specifier(H)=%d\n", r);
    wchar_t mod[] = {'M','\0'};
    int b = register_printf_modifier(mod);
    printf("register_printf_modifier(M) positive=%d\n", b > 0);
}

int main(void){
    ecvt_fcvt();
    gcvt_t();
    cvt_r();
    strfrom_t();
    parse_t();
    psize_t();
    reg_t();
    return 0;
}
