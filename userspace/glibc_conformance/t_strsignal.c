#include <stdio.h>
#include <string.h>
#include <signal.h>
int main(void){
    int sigs[] = {1,2,4,6,8,9,11,13,15,17,19,28,31};
    for (size_t i=0;i<sizeof sigs/sizeof sigs[0];i++)
        printf("sig%d=%s\n", sigs[i], strsignal(sigs[i]));
    return 0;
}
