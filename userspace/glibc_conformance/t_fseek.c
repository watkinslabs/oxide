#include <stdio.h>
int main(void){
    FILE *f = fopen("/tmp/oxide_seek.txt","w+");
    if(!f){ printf("fail\n"); return 1; }
    fputs("0123456789", f);
    fseek(f, 3, SEEK_SET); printf("tell=%ld getc=%c\n", ftell(f), fgetc(f));
    fseek(f, -2, SEEK_END); printf("end_tell=%ld getc=%c\n", ftell(f), fgetc(f));
    rewind(f); printf("rewind_tell=%ld\n", ftell(f));
    ungetc('Z', f); printf("ungetc=%c\n", fgetc(f));
    fclose(f);
    return 0;
}
