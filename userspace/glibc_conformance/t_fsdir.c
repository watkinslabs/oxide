/* dirent readdir_r/telldir/seekdir + glob64 + ftw64/nftw64 + fstab vs host
   glibc. Deterministic: build a known tmp tree, sort readdir output, round-trip
   one telldir/seekdir position, glob64 our own files, count an nftw64 walk.
   Both the host-glibc and oxide-libc builds run on the same host kernel, so
   /etc/fstab and readdir order match. All temp files/dirs are cleaned up. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <glob.h>
#include <ftw.h>
#include <fstab.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

static char names[64][256];
static int nn;
static int cmp(const void *a, const void *b){ return strcmp(a, b); }

static int walk_count;
static int nftw_cb(const char *p, const struct stat64 *s, int flag, struct FTW *w){
    (void)p; (void)s; (void)flag; (void)w; walk_count++; return 0;
}
static int ftw_cb(const char *p, const struct stat64 *s, int flag){
    (void)p; (void)s; (void)flag; walk_count++; return 0;
}

int main(void){
    const char *root = "/tmp/oxide_t_fsdir";
    char path[256];
    mkdir(root, 0755);
    const char *files[] = {"alpha", "beta", "gamma"};
    for (size_t i=0;i<3;i++){ snprintf(path,sizeof path,"%s/%s",root,files[i]); close(creat(path,0644)); }
    snprintf(path,sizeof path,"%s/sub",root); mkdir(path,0755);
    snprintf(path,sizeof path,"%s/sub/leaf",root); close(creat(path,0644));

    /* readdir_r: collect names, sort, print (order-independent) */
    DIR *d = opendir(root);
    struct dirent ent, *res;
    nn = 0;
    while (readdir_r(d, &ent, &res) == 0 && res){
        strcpy(names[nn++], res->d_name);
    }
    qsort(names, nn, sizeof names[0], cmp);
    printf("readdir_r count=%d\n", nn);
    for (int i=0;i<nn;i++) printf("  %s\n", names[i]);

    /* telldir/seekdir round-trip: rewind, read 2 entries saving pos before the
       3rd, read 3rd name, seek back, re-read and confirm same name. */
    rewinddir(d);
    struct dirent *e;
    e = readdir(d); /* 1 */
    e = readdir(d); /* 2 */
    long pos = telldir(d);
    e = readdir(d); /* 3 */
    char first[256]; first[0]=0;
    if (e) strcpy(first, e->d_name);
    seekdir(d, pos);
    e = readdir(d); /* re-read the 3rd */
    char again[256]; again[0]=0;
    if (e) strcpy(again, e->d_name);
    printf("seekdir roundtrip match=%d\n", strcmp(first, again) == 0);
    closedir(d);

    /* glob64 over our created files */
    glob64_t g;
    int gr = glob64("/tmp/oxide_t_fsdir/*a", 0, NULL, &g);
    printf("glob64 ret=%d pathc=%zu\n", gr, (size_t)g.gl_pathc);
    for (size_t i=0;i<g.gl_pathc;i++) printf("  %s\n", g.gl_pathv[i]);
    globfree64(&g);

    /* ftw64 / nftw64 visited count over the tree (a/b/g + sub + sub/leaf + root) */
    walk_count = 0;
    nftw64(root, nftw_cb, 16, FTW_PHYS);
    printf("nftw64 count=%d\n", walk_count);
    walk_count = 0;
    ftw64(root, ftw_cb, 16);
    printf("ftw64 count=%d\n", walk_count);

    /* fstab: read /etc/fstab and report whether the root mount ("/") entry
       exists; getfsfile matches by mount point. Stable across both builds. */
    setfsent();
    struct fstab *fe = getfsfile("/");
    printf("getfsfile(/)=%d\n", fe != NULL);
    if (fe) printf("  fs_type=%s passno=%d\n", fe->fs_type, fe->fs_passno);
    endfsent();

    /* cleanup */
    for (size_t i=0;i<3;i++){ snprintf(path,sizeof path,"%s/%s",root,files[i]); unlink(path); }
    snprintf(path,sizeof path,"%s/sub/leaf",root); unlink(path);
    snprintf(path,sizeof path,"%s/sub",root); rmdir(path);
    rmdir(root);
    return 0;
}
