/* Linux IPV6 hop-limit getsockopt default-resolution corpus (N18). */
#define _GNU_SOURCE
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
static int g(int fd,int opt){int v=-9;socklen_t l=sizeof v;getsockopt(fd,IPPROTO_IPV6,opt,&v,&l);return v;}
int main(void){
 int t=socket(AF_INET6,SOCK_STREAM,0), u=socket(AF_INET6,SOCK_DGRAM,0);
 /* Fresh socket: unicast hops resolve to the default 64, multicast to 1. */
 printf("unicast_default=%d\n",g(t,IPV6_UNICAST_HOPS));
 printf("multicast_default=%d\n",g(u,IPV6_MULTICAST_HOPS));
 /* Setting -1 selects the default; readback shows the resolved value. */
 int m1=-1; setsockopt(t,IPPROTO_IPV6,IPV6_UNICAST_HOPS,&m1,sizeof m1);
 printf("unicast_neg1=%d\n",g(t,IPV6_UNICAST_HOPS));
 setsockopt(u,IPPROTO_IPV6,IPV6_MULTICAST_HOPS,&m1,sizeof m1);
 printf("multicast_neg1=%d\n",g(u,IPV6_MULTICAST_HOPS));
 /* An explicit value round-trips. */
 int v=30; setsockopt(t,IPPROTO_IPV6,IPV6_UNICAST_HOPS,&v,sizeof v);
 printf("unicast_30=%d\n",g(t,IPV6_UNICAST_HOPS));
 close(t);close(u);return 0;}
