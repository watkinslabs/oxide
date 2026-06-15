#include <stdio.h>
#include <fenv.h>

static const char *roundname(int m){
    if(m==FE_TONEAREST)  return "tonearest";
    if(m==FE_DOWNWARD)   return "downward";
    if(m==FE_UPWARD)     return "upward";
    if(m==FE_TOWARDZERO) return "towardzero";
    return "unknown";
}

int main(void){
    feclearexcept(FE_ALL_EXCEPT);
    printf("cleared inexact=%d invalid=%d\n",
           fetestexcept(FE_INEXACT)!=0, fetestexcept(FE_INVALID)!=0);

    /* inexact via feraiseexcept (deterministic; libm flag side effects are
       not part of the fenv contract under test) */
    feraiseexcept(FE_INEXACT);
    printf("after raise inexact=%d\n", fetestexcept(FE_INEXACT)!=0);

    /* invalid via feraiseexcept */
    feclearexcept(FE_ALL_EXCEPT);
    feraiseexcept(FE_INVALID);
    printf("after raise invalid=%d\n", fetestexcept(FE_INVALID)!=0);

    /* round-mode round-trip through all four */
    int modes[4] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };
    for(int i=0;i<4;i++){
        int rc = fesetround(modes[i]);
        printf("set %-10s rc=%d got=%s\n",
               roundname(modes[i]), rc!=0, roundname(fegetround()));
    }
    fesetround(FE_TONEAREST);

    /* invalid mode rejected */
    printf("set bogus rc!=0: %d round=%s\n",
           fesetround(12345)!=0, roundname(fegetround()));

    /* feraiseexcept + feclearexcept */
    feclearexcept(FE_ALL_EXCEPT);
    feraiseexcept(FE_OVERFLOW | FE_DIVBYZERO);
    printf("raised overflow=%d divbyzero=%d underflow=%d\n",
           fetestexcept(FE_OVERFLOW)!=0,
           fetestexcept(FE_DIVBYZERO)!=0,
           fetestexcept(FE_UNDERFLOW)!=0);
    feclearexcept(FE_OVERFLOW);
    printf("after clear overflow: overflow=%d divbyzero=%d\n",
           fetestexcept(FE_OVERFLOW)!=0,
           fetestexcept(FE_DIVBYZERO)!=0);
    feclearexcept(FE_ALL_EXCEPT);
    printf("all clear=%d\n", fetestexcept(FE_ALL_EXCEPT)==0);

    /* exception-flag save/restore */
    feraiseexcept(FE_INEXACT);
    fexcept_t saved;
    fegetexceptflag(&saved, FE_ALL_EXCEPT);
    feclearexcept(FE_ALL_EXCEPT);
    fesetexceptflag(&saved, FE_ALL_EXCEPT);
    printf("restored inexact=%d\n", fetestexcept(FE_INEXACT)!=0);
    feclearexcept(FE_ALL_EXCEPT);
    return 0;
}
