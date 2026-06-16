/* aliases DB: negative lookup + enumeration reset. The positive path depends on
 * nsswitch (aliases:) so only the deterministic NULL path is compared. vs host. */
#define _GNU_SOURCE
#include <aliases.h>
#include <stdio.h>
int main(void) {
    struct aliasent *a = getaliasbyname("__no_such_alias_xyz__");
    printf("byname_null=%d\n", a == NULL);
    char buf[1024]; struct aliasent ent, *res = (struct aliasent *)1;
    int r = getaliasbyname_r("__no_such_alias_xyz__", &ent, buf, sizeof buf, &res);
    printf("byname_r=%d res_null=%d\n", r, res == NULL);
    setaliasent(); endaliasent();
    printf("setend_ok=1\n");
    return 0;
}
