/* getusershell/setusershell/endusershell enumeration over /etc/shells vs host. */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>

static void dump(const char *tag){
    printf("%s", tag);
    for(int i=0;i<64;i++){
        char *s = getusershell();
        printf(" [%d]=%s", i, s ? s : "(null)");
        if(!s) break;
    }
    printf("\n");
}

int main(void){
    dump("first");
    setusershell();
    dump("after_set");
    endusershell();
    dump("after_end");
    return 0;
}
