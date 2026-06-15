#include <stdio.h>
int main(void){
    printf("%g %g %g %g\n", 100000.0, 1000000.0, 0.0001, 0.00001);
    printf("%g %g %g\n", 3.14159265, 1.0, 0.0);
    printf("%.3g %.10g\n", 3.14159, 2.0/3.0);
    printf("%G %e\n", 1234567.0, 1234567.0);
    printf("%g %g\n", 1e20, 1e-20);
    return 0;
}
