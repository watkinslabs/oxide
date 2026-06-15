#include <stdio.h>
#include <math.h>
int main(void){
    double vs[] = {1.0, 2.0, 0.5, 0.1, 3.14159265358979, 0.0, -0.0,
                   1024.0, 1.0/3.0, 65504.0, 2.220446049250313e-16, -8.75};
    for (size_t i=0;i<sizeof vs/sizeof vs[0];i++)
        printf("a[%zu]=%a A=%A\n", i, vs[i], vs[i]);
    /* explicit precision (rounding, incl carry) */
    printf("p0=%.0a p1=%.1a p2=%.2a p4=%.4a\n", 0.1, 0.1, 0.1, 0.1);
    printf("carry=%.0a half=%.2a\n", 1.9999999999999, 0.1);
    /* width / flags */
    printf("w=[%14a] left=[%-14a] plus=[%+a] zero=[%014a]\n", 1.5, 1.5, 1.5, 1.5);
    /* subnormal + inf/nan */
    printf("sub=%a inf=%a ninf=%a nan=%a\n", 0x1p-1074, INFINITY, -INFINITY, NAN);
    return 0;
}
