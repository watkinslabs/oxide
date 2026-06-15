#include <stdio.h>
#include <setjmp.h>
static jmp_buf jb;
static void deep(int n){ if(n==0) longjmp(jb, 77); deep(n-1); }
int main(void){
    volatile int hops=0;
    int r = setjmp(jb);
    if(r==0){ hops++; deep(5); printf("unreachable\n"); }
    printf("r=%d hops=%d\n", r, hops);
    return 0;
}
