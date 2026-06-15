#include <stdio.h>
#include <stdlib.h>
int main(void){
    FILE *f = fopen("/tmp/oxide_gl.txt","w+");
    fputs("alpha\nbeta\ngamma\n", f); rewind(f);
    char *line = NULL; size_t cap = 0; ssize_t n; int i=0;
    while((n = getline(&line, &cap, f)) > 0){ line[n>0&&line[n-1]=='\n'?n-1:n]=0; printf("[%d]%s len=%zd\n", i++, line, n); }
    free(line); fclose(f);
    return 0;
}
