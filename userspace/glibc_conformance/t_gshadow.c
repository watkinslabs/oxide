/* gshadow: sgetsgent (parse), putsgent (serialize via tmpfile), getsgnam(neg). vs host. */
#define _GNU_SOURCE
#include <gshadow.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    struct sgrp *g = sgetsgent("staff:!:alice,bob:carol,dave");
    printf("parse=%d name=%s pwd=%s\n", g != NULL, g->sg_namp, g->sg_passwd);
    printf("adm=%s,%s end=%d\n", g->sg_adm[0], g->sg_adm[1], g->sg_adm[2] == NULL);
    printf("mem=%s,%s end=%d\n", g->sg_mem[0], g->sg_mem[1], g->sg_mem[2] == NULL);

    FILE *t = tmpfile();
    putsgent(g, t);
    rewind(t);
    char line[256] = {0}; fgets(line, sizeof line, t); fclose(t);
    printf("putsgent=[%s]\n", line);

    printf("getsgnam_null=%d\n", getsgnam("__no_such_group_xyz__") == NULL);
    return 0;
}
