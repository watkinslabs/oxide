#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(void){
    char tmpl[] = "/tmp/oxide_mkXXXXXX";
    int fd = mkstemp(tmpl);
    if(fd < 0){ printf("mkstemp-fail\n"); return 1; }
    write(fd, "ok", 2); close(fd);
    printf("created=%d xs_replaced=%d\n", fd>=0, tmpl[10]!='X');
    unlink(tmpl);
    return 0;
}
