#define _GNU_SOURCE
#include <stdio.h>
#include <search.h>
#include <string.h>

static int icmp(const void *a, const void *b){ return *(const int*)a - *(const int*)b; }

static void act(const void *nodep, VISIT which, int depth){
    (void)depth;
    int key = **(int* const*)nodep;
    if (which == postorder || which == leaf) printf("%d ", key);
}

int main(void){
    /* tsearch / tfind / twalk in-order */
    void *root = NULL;
    int vals[] = {5,3,8,1,4,7,9,3};
    for (size_t i=0;i<sizeof vals/sizeof vals[0];i++)
        tsearch(&vals[i], &root, icmp);
    printf("inorder: "); twalk(root, act); printf("\n");
    int probe = 7;
    printf("find7=%d find6=%d\n", tfind(&probe, &root, icmp)!=NULL, (probe=6, tfind(&probe, &root, icmp)!=NULL));
    probe = 8; tdelete(&probe, &root, icmp);
    printf("after_del8_find8=%d\n", (probe=8, tfind(&probe,&root,icmp)!=NULL));
    printf("inorder2: "); twalk(root, act); printf("\n");

    /* lsearch / lfind */
    int tab[16]; size_t n = 0;
    int a=10,b=20,c=10;
    lsearch(&a, tab, &n, sizeof(int), icmp);
    lsearch(&b, tab, &n, sizeof(int), icmp);
    lsearch(&c, tab, &n, sizeof(int), icmp); /* dup, no growth */
    int miss=99;
    printf("n=%zu lfind20=%d lfind99=%d\n", n,
           *(int*)lfind(&b, tab, &n, sizeof(int), icmp),
           lfind(&miss, tab, &n, sizeof(int), icmp)==NULL);
    return 0;
}
