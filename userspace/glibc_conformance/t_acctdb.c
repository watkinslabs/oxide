/* putgrent/putspent (serialize via tmpfile) + lckpwdf/ulckpwdf. vs host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <grp.h>
#include <shadow.h>

int main(void) {
    char *mem[] = { "alice", "bob", NULL };
    struct group g = { "staff", "x", 42, mem };
    FILE *t = tmpfile();
    putgrent(&g, t);
    rewind(t);
    char line[256] = {0};
    fgets(line, sizeof line, t);
    printf("grent=[%s]\n", line); /* staff:x:42:alice,bob\n */
    fclose(t);

    struct spwd s = { "alice", "!locked", 19000, 0, 99999, 7, -1, -1, (unsigned long)-1 };
    FILE *t2 = tmpfile();
    putspent(&s, t2);
    rewind(t2);
    char line2[256] = {0};
    fgets(line2, sizeof line2, t2);
    printf("spent=[%s]\n", line2); /* alice:!locked:19000:0:99999:7:::\n */
    fclose(t2);

    /* lckpwdf result depends on perms but is identical host-vs-ours (same user).
     * If it locks, a second attempt must report already-locked; unlock matches. */
    int l1 = lckpwdf();
    int l2 = lckpwdf();          /* if l1==0, this is the already-held case */
    int u1 = ulckpwdf();
    printf("lock_consistent=%d\n", (l1 == 0) ? (l2 == -1 && u1 == 0) : (u1 == -1));
    return 0;
}
