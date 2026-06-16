/* twalk_r vs host glibc — tree walk passing an opaque closure to the action. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <search.h>
static int cmp(const void *a, const void *b){ int x=*(const int*)a, y=*(const int*)b; return (x>y)-(x<y); }
static int vals[] = {50,30,70,20,40,60,80,10};
struct ctx { long sum; int count; };
static void act(const void *nodep, VISIT which, void *closure){
    struct ctx *c = closure;
    if(which==postorder || which==leaf){
        int k = **(int* const*)nodep;
        c->sum += k; c->count++;
        printf("visit %d (which=%d)\n", k, which);
    }
}
int main(void){
    void *root = NULL;
    for(int i=0;i<8;i++) tsearch(&vals[i], &root, cmp);
    struct ctx c = {0,0};
    twalk_r(root, act, &c);
    printf("sum=%ld count=%d\n", c.sum, c.count);
    twalk_r(NULL, act, &c); /* null root: no-op */
    printf("after-null count=%d\n", c.count);
    return 0;
}
