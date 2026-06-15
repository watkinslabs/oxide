#include <stdio.h>
#include <string.h>
int main(void){
    char b[64]; strcpy(b,"foo"); strcat(b,"bar");
    printf("cat=%s len=%zu\n", b, strlen(b));
    printf("cmp=%d %d\n", strcmp("abc","abd")<0, strncmp("abcX","abcY",3));
    printf("chr=%ld str=%ld\n", strchr(b,'b')-b, (long)(strstr(b,"bar")?strstr(b,"bar")-b:-1));
    char m[8]; memset(m,'x',7); m[7]=0; printf("memset=%s\n", m);
    char d[8]; memcpy(d,"copyme",7); printf("memcpy=%s memcmp=%d\n", d, memcmp("ab","ab",2));
    return 0;
}
