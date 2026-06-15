/* argz vector audit vs host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <argz.h>
#include <stdlib.h>
#include <string.h>

int main(void){
    char *argz = NULL; size_t len = 0;
    /* clean field list (no consecutive/trailing separators — glibc's empty-
       field handling there is idiosyncratic and out of scope). */
    argz_create_sep("a:bb:ccc", ':', &argz, &len);
    printf("count=%zu len=%zu\n", argz_count(argz, len), len);

    argz_add(&argz, &len, "dddd");
    printf("count2=%zu\n", argz_count(argz, len));

    /* iterate */
    printf("iter:");
    for (char *e = argz_next(argz, len, NULL); e; e = argz_next(argz, len, e))
        printf(" %s", e);
    printf("\n");

    /* extract */
    size_t n = argz_count(argz, len);
    char **v = malloc((n+1)*sizeof(char*));
    argz_extract(argz, len, v);
    printf("extract: %s|%s|%s|%s last=%p\n", v[0], v[1], v[2], v[3], (void*)v[n]);
    free(v);

    /* create from argv */
    char *av[] = {"one","two","three",NULL};
    char *az2=NULL; size_t l2=0;
    argz_create(av, &az2, &l2);
    printf("fromargv count=%zu\n", argz_count(az2, l2));

    /* stringify (copy first so we keep argz intact) */
    char *copy = malloc(len); memcpy(copy, argz, len);
    argz_stringify(copy, len, ',');
    printf("stringify=%s\n", copy);
    free(copy);

    free(argz); free(az2);
    return 0;
}
