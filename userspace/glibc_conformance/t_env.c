#include <stdio.h>
#include <stdlib.h>
int main(void){
    setenv("OXIDE_T", "val42", 1);
    printf("get=%s\n", getenv("OXIDE_T"));
    setenv("OXIDE_T", "override", 1);
    printf("ovr=%s\n", getenv("OXIDE_T"));
    unsetenv("OXIDE_T");
    printf("unset=%d\n", getenv("OXIDE_T")==NULL);
    return 0;
}
