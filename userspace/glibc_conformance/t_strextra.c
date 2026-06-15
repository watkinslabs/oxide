#include <stdio.h>
#include <string.h>
int main(void){
    char s[]="a,b,,c"; char *save; int i=0;
    for(char *t=strtok_r(s,",",&save); t; t=strtok_r(NULL,",",&save)) printf("tok%d=%s ", i++, t);
    printf("\n");
    printf("spn=%zu cspn=%zu pbrk=%ld rchr=%ld\n",
        strspn("abcXYZ","abc"), strcspn("abcX","X"),
        (long)(strpbrk("hello","l")-"hello"), (long)(strrchr("a/b/c",'/')- "a/b/c"));
    char d[8]; strncpy(d,"hi",8); printf("ncpy=%s|%d\n", d, d[3]==0);
    char m[16]="0123456789"; memmove(m+2,m,5); m[7]=0; printf("move=%s\n", m);
    return 0;
}
