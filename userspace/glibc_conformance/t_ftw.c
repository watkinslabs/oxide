/* ftw/nftw vs host glibc over a temp tree (visited entries sorted for a
   readdir-order-independent comparison). */
#define _GNU_SOURCE
#include <stdio.h>
#include <ftw.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

static char lines[64][320];
static int n;

static int cb(const char *p, const struct stat *s, int flag, struct FTW *w){
    (void)s;
    snprintf(lines[n], sizeof lines[0], "%s f=%d base=%d lvl=%d", p, flag, w->base, w->level);
    n++;
    return 0;
}
static int cmp(const void *a, const void *b){ return strcmp(a, b); }

int main(void){
    const char *root = "/tmp/oxide_ftw_test";
    /* build: root/{a.txt, b.txt, sub/c.txt} */
    mkdir(root, 0755);
    char path[256];
    snprintf(path, sizeof path, "%s/a.txt", root); close(creat(path, 0644));
    snprintf(path, sizeof path, "%s/b.txt", root); close(creat(path, 0644));
    snprintf(path, sizeof path, "%s/sub", root); mkdir(path, 0755);
    snprintf(path, sizeof path, "%s/sub/c.txt", root); close(creat(path, 0644));

    n = 0;
    nftw(root, cb, 16, FTW_PHYS);
    qsort(lines, n, sizeof lines[0], cmp);
    printf("count=%d\n", n);
    for (int i=0;i<n;i++) printf("%s\n", lines[i]);

    /* cleanup */
    snprintf(path, sizeof path, "%s/a.txt", root); unlink(path);
    snprintf(path, sizeof path, "%s/b.txt", root); unlink(path);
    snprintf(path, sizeof path, "%s/sub/c.txt", root); unlink(path);
    snprintf(path, sizeof path, "%s/sub", root); rmdir(path);
    rmdir(root);
    return 0;
}
