#include <stdio.h>
#include <string.h>
int main(void){
    FILE *f = fopen("/tmp/oxide_conf_file.txt","w");
    if(!f){ printf("fopen-w-fail\n"); return 1; }
    fprintf(f, "line1=%d\n", 42); fputs("line2\n", f); fwrite("raw7\n",1,5,f);
    fclose(f);
    f = fopen("/tmp/oxide_conf_file.txt","r");
    if(!f){ printf("fopen-r-fail\n"); return 1; }
    char buf[64]; int ln=0;
    while(fgets(buf,sizeof buf,f)){ buf[strcspn(buf,"\n")]=0; printf("[%d]%s\n", ln++, buf); }
    fclose(f);
    return 0;
}
