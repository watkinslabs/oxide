/* fts_open/read/close + fts_set vs host glibc over a self-built temp tree.
 * Deterministic: fixed tree, comparator-sorted, prints info/level/name/path +
 * a stat field, so host and ours must produce identical output. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <fts.h>

static const char *infoname(int i){
    switch(i){
    case FTS_D:return "D"; case FTS_DC:return "DC"; case FTS_DEFAULT:return "DEFAULT";
    case FTS_DNR:return "DNR"; case FTS_DOT:return "DOT"; case FTS_DP:return "DP";
    case FTS_ERR:return "ERR"; case FTS_F:return "F"; case FTS_NS:return "NS";
    case FTS_NSOK:return "NSOK"; case FTS_SL:return "SL"; case FTS_SLNONE:return "SLNONE";
    default:return "?";
    }
}
static int cmp(const FTSENT **a, const FTSENT **b){
    return strcmp((*a)->fts_name, (*b)->fts_name);
}
static void mk(const char *p){ mkdir(p,0755); }
static void wr(const char *p){ int fd=open(p,O_CREAT|O_WRONLY|O_TRUNC,0644); if(fd>=0){ write(fd,"x",1); close(fd); } }

int main(void){
    char root[] = "/tmp/oxide_fts_XXXXXX";
    if(!mkdtemp(root)){ perror("mkdtemp"); return 1; }
    char b[512];
    snprintf(b,sizeof b,"%s/sub",root); mk(b);
    snprintf(b,sizeof b,"%s/sub/deep",root); mk(b);
    snprintf(b,sizeof b,"%s/sub/deep/leaf.txt",root); wr(b);
    snprintf(b,sizeof b,"%s/sub/a.txt",root); wr(b);
    snprintf(b,sizeof b,"%s/sub/b.txt",root); wr(b);
    snprintf(b,sizeof b,"%s/empty",root); mk(b);
    snprintf(b,sizeof b,"%s/top.txt",root); wr(b);
    snprintf(b,sizeof b,"%s/dangling",root); { char t[512]; snprintf(t,sizeof t,"%s/nope",root); symlink(t,b); }
    snprintf(b,sizeof b,"%s/link_to_top",root); { char t[512]; snprintf(t,sizeof t,"%s/top.txt",root); symlink(t,b); }

    /* relative-name reporting: chop the random prefix so output is stable. */
    size_t rlen = strlen(root);

    char *argv[] = { root, NULL };
    FTS *f = fts_open(argv, FTS_PHYSICAL, cmp);
    if(!f){ perror("fts_open"); return 1; }
    FTSENT *e; int n=0;
    while((e = fts_read(f)) != NULL){
        const char *rel = e->fts_path + (strncmp(e->fts_path,root,rlen)==0 ? rlen : 0);
        if(*rel=='\0') rel="/";
        long sz = (e->fts_info==FTS_NS||e->fts_info==FTS_SLNONE)?0:(long)e->fts_statp->st_size;
        int isdir = (e->fts_info==FTS_D||e->fts_info==FTS_DP);
        char nl[24];
        /* glibc only sets fts_nlink/ino/dev for directories. */
        if(isdir) snprintf(nl,sizeof nl,"%lu",(unsigned long)e->fts_nlink); else snprintf(nl,sizeof nl,"-");
        /* root fts_name is the random mkdtemp dir; normalize for determinism. */
        const char *nm = (e->fts_level==0) ? "ROOT" : e->fts_name;
        printf("%-7s lvl=%d name=%-12s path=%s nlink=%s sz=%s\n",
               infoname(e->fts_info), e->fts_level, nm, rel, nl,
               (e->fts_info==FTS_D)?"-":(sz?"y":"n"));
        /* exercise fts_set: skip descending into "empty" */
        if(e->fts_info==FTS_D && strcmp(e->fts_name,"empty")==0) fts_set(f,e,FTS_SKIP);
        n++;
    }
    fts_close(f);
    printf("count=%d\n", n);

    /* logical walk: link_to_top resolves to a file (FTS_F), dangling -> SLNONE */
    f = fts_open(argv, FTS_LOGICAL, cmp);
    int nl=0;
    while((e = fts_read(f)) != NULL){
        if(e->fts_level==1) printf("L %-7s %s\n", infoname(e->fts_info), e->fts_name);
        nl++;
    }
    fts_close(f);

    /* cleanup */
    char rmcmd[600]; snprintf(rmcmd,sizeof rmcmd,"rm -rf '%s'",root); if(system(rmcmd)){}
    return 0;
}
