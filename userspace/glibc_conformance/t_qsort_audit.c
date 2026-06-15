/* qsort/bsearch audit vs host glibc: varied element sizes/types, ties, empty/
   single, struct sort, qsort_r, bsearch hit/miss. Sorted output is
   deterministic regardless of sort algorithm. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int icmp(const void *a, const void *b){ int x=*(const int*)a,y=*(const int*)b; return (x>y)-(x<y); }
static int ccmp(const void *a, const void *b){ return *(const char*)a - *(const char*)b; }
static int scmp(const void *a, const void *b){ return strcmp(*(char*const*)a, *(char*const*)b); }
struct rec { int key; int ord; };
static int rcmp(const void *a, const void *b){ return ((const struct rec*)a)->key - ((const struct rec*)b)->key; }
static int rcmp_r(const void *a, const void *b, void *ctx){ int s=*(int*)ctx; return s*(((const struct rec*)a)->key - ((const struct rec*)b)->key); }

int main(void){
    int v[] = {5,2,8,2,9,1,5,3,2,7};
    qsort(v, 10, sizeof(int), icmp);
    printf("ints:"); for(int i=0;i<10;i++) printf("%d", v[i]); printf("\n");

    char s[] = "thequickbrownfox";
    qsort(s, strlen(s), 1, ccmp);
    printf("chars:%s\n", s);

    const char *w[] = {"banana","apple","cherry","apple","date"};
    qsort(w, 5, sizeof(char*), scmp);
    printf("strs:"); for(int i=0;i<5;i++) printf("%s,", w[i]); printf("\n");

    struct rec r[] = {{3,0},{1,1},{3,2},{2,3},{1,4}};
    qsort(r, 5, sizeof r[0], rcmp);
    printf("recs:"); for(int i=0;i<5;i++) printf("(%d)", r[i].key); printf("\n");

    int desc = -1;
    qsort_r(r, 5, sizeof r[0], rcmp_r, &desc);
    printf("recs_desc:"); for(int i=0;i<5;i++) printf("(%d)", r[i].key); printf("\n");

    /* edge: empty + single */
    int one[] = {42}; qsort(one, 1, sizeof(int), icmp); qsort(v, 0, sizeof(int), icmp);
    printf("one=%d\n", one[0]);

    /* bsearch on sorted ints */
    int sorted[] = {1,2,3,5,8,13,21};
    for(int k=0;k<10;k++){ int *p = bsearch(&k, sorted, 7, sizeof(int), icmp); printf("%d%s ", k, p?"+":"-"); }
    printf("\n");
    return 0;
}
