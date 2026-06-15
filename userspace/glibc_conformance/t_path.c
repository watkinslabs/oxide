#include <stdio.h>
#include <libgen.h>
#include <string.h>
int main(void){
    char a[]="/usr/local/bin/prog"; char b[]="/usr/local/bin/prog";
    printf("base=%s dir=%s\n", basename(a), dirname(b));
    char c[]="noslash"; char d[]="noslash";
    printf("base2=%s dir2=%s\n", basename(c), dirname(d));
    char e[]="/"; printf("baseroot=%s\n", basename(e));
    return 0;
}
