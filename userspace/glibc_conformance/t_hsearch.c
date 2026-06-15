#define _GNU_SOURCE
#include <stdio.h>
#include <search.h>
#include <string.h>

struct node { struct node *f, *b; int v; };

int main(void){
    /* hsearch global table */
    hcreate(16);
    char *keys[] = {"alpha","beta","gamma","delta"};
    int vals[] = {1,2,3,4};
    for (int i=0;i<4;i++){
        ENTRY e = { keys[i], (void*)(long)vals[i] };
        hsearch(e, ENTER);
    }
    ENTRY q = { "gamma", NULL };
    ENTRY *r = hsearch(q, FIND);
    printf("gamma=%ld\n", r ? (long)r->data : -1L);
    ENTRY miss = { "zeta", NULL };
    printf("zeta_found=%d\n", hsearch(miss, FIND) != NULL);
    /* ENTER on existing key returns existing entry, no dup */
    ENTRY dup = { "beta", (void*)99 };
    ENTRY *d = hsearch(dup, ENTER);
    printf("beta_after_dup_enter=%ld\n", (long)d->data); /* still 2, not 99 */
    hdestroy();

    /* insque / remque: build 1<->2<->3, remove 2, walk */
    struct node n1={0,0,1}, n2={0,0,2}, n3={0,0,3};
    insque(&n1, NULL);
    insque(&n2, &n1);
    insque(&n3, &n2);
    printf("list:"); for (struct node *p=&n1;p;p=p->f) printf(" %d", p->v); printf("\n");
    remque(&n2);
    printf("after_rem:"); for (struct node *p=&n1;p;p=p->f) printf(" %d", p->v); printf("\n");
    return 0;
}
