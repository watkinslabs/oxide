#include <stdio.h>
int main(void){
    printf("int=%d uint=%u hex=%x HEX=%X oct=%o\n", -42, 42u, 255, 255, 64);
    printf("ll=%lld ull=%llu\n", -1234567890123LL, 9876543210ULL);
    printf("str=%s char=%c pct=%%\n", "hello", 'Z');
    printf("pad=[%5d][%-5d][%05d][%+d]\n", 42, 42, 42, 42);
    printf("flt=%f e=%e g=%g\n", 3.14159, 31415.9, 0.0001234);
    printf("prec=%.3f width=%8.2f\n", 2.0/3.0, 3.14159);
    printf("ptr_nonnull=%d\n", (void*)main != 0);
    return 0;
}
