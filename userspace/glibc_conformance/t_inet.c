#include <stdio.h>
#include <arpa/inet.h>
int main(void){
    struct in_addr a; inet_pton(AF_INET, "192.168.1.1", &a);
    char buf[64]; inet_ntop(AF_INET, &a, buf, sizeof buf); printf("v4=%s\n", buf);
    printf("htons=%u htonl=%u\n", htons(0x1234), htonl(0x12345678)==0x78563412u || htonl(0x12345678)==0x12345678u);
    struct in6_addr a6; int r = inet_pton(AF_INET6, "2001:db8::1", &a6);
    char b6[64]; inet_ntop(AF_INET6, &a6, b6, sizeof b6); printf("v6r=%d v6=%s\n", r, b6);
    return 0;
}
