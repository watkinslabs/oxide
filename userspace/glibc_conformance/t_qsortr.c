#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
static int cmp(const void*a,const void*b,void*ctx){ int s=*(int*)ctx; return s*(*(const int*)a-*(const int*)b); }
int main(void){
    int v[]={3,1,4,1,5,9,2,6}; int desc=-1;
    qsort_r(v,8,sizeof(int),cmp,&desc);
    for(int i=0;i<8;i++) printf("%d",v[i]); printf("\n");
    return 0;
}
