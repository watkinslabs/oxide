/* epoll: register a pipe read-end, write a byte, epoll_wait reports it ready;
 * empty epoll times out. Exercises epoll_create1/ctl/wait + epoll_event ABI. */
#include <stdio.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <string.h>

int main(void) {
    int ep = epoll_create1(0);
    if (ep < 0) { printf("create fail\n"); return 1; }
    int p[2];
    if (pipe(p) != 0) { printf("pipe fail\n"); return 1; }

    struct epoll_event ev; memset(&ev, 0, sizeof ev);
    ev.events = EPOLLIN; ev.data.fd = p[0];
    if (epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &ev) != 0) { printf("ctl fail\n"); return 1; }

    struct epoll_event out[4];
    int n = epoll_wait(ep, out, 4, 10);          /* empty → timeout 0 */
    printf("empty=%d\n", n);

    if (write(p[1], "x", 1) != 1) { printf("write fail\n"); return 1; }
    n = epoll_wait(ep, out, 4, 100);             /* ready → 1 */
    printf("ready=%d in=%d fd=%d\n", n, (n>0 && (out[0].events & EPOLLIN)) ? 1 : 0,
           (n>0 && out[0].data.fd == p[0]) ? 1 : 0);
    return 0;
}
