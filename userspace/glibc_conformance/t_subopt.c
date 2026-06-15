#include <stdio.h>
#include <stdlib.h>
enum { RO, RW, NAME };
static char *const toks[] = { [RO]="ro", [RW]="rw", [NAME]="name", NULL };
int main(void){
    char opts[] = "rw,name=disk0,bogus,ro";
    char *sub = opts, *val;
    int idx;
    while (*sub != '\0') {
        idx = getsubopt(&sub, toks, &val);
        printf("idx=%d val=%s\n", idx, val ? val : "(null)");
    }
    return 0;
}
