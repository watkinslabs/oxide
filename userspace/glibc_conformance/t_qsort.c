#include <stdio.h>
#include <stdlib.h>
static int cmp(const void*a,const void*b){return *(const int*)a-*(const int*)b;}
int main(void){
    int v[]={5,3,8,1,9,2,7,4,6,0};
    qsort(v,10,sizeof(int),cmp);
    for(int i=0;i<10;i++) printf("%d",v[i]); printf("\n");
    int key=7; int*r=bsearch(&key,v,10,sizeof(int),cmp);
    printf("found=%ld\n", r? r-v : -1);
    return 0;
}
