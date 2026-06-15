#include <stdio.h>
int main(void){
    printf("%2$d %1$d %3$s\n", 10, 20, "x");
    printf("%1$d %1$d\n", 7);
    printf("%*d|%-*d\n", 5, 42, 5, 42);
    printf("%2$.*1$f\n", 3, 3.14159);
    printf("%3$s %1$s %2$s\n", "a", "b", "c");
    return 0;
}
