#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

static void lookup(const char *name, int socktype)
{
    struct addrinfo hints;
    struct addrinfo *res = 0;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = socktype;
    hints.ai_flags = AI_PASSIVE;

    int r = getaddrinfo(0, name, &hints, &res);
    printf("%s/%s r=%d", name, socktype == SOCK_DGRAM ? "udp" : "tcp", r);
    if (r == 0 && res && res->ai_addr) {
        struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
        printf(" family=%d sock=%d port=%u", res->ai_family, res->ai_socktype, ntohs(sin->sin_port));
    }
    printf("\n");
    if (res)
        freeaddrinfo(res);
}

int main(void)
{
    lookup("http", SOCK_STREAM);
    lookup("domain", SOCK_DGRAM);

    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;
    printf("numericserv_name r=%d\n", getaddrinfo(0, "http", &hints, 0));
    return 0;
}
