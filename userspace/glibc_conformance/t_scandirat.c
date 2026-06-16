/* scandirat vs host glibc over a temp dir (relative to an opened dirfd). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
static int only_txt(const struct dirent *e){ const char*p=strrchr(e->d_name,'.'); return p && strcmp(p,".txt")==0; }
int main(void){
    char root[]="/tmp/oxide_sdat_XXXXXX";
    if(!mkdtemp(root)){ perror("mkdtemp"); return 1; }
    char b[300];
    const char *names[]={"b.txt","a.txt","c.log","sub"};
    for(int i=0;i<3;i++){ snprintf(b,sizeof b,"%s/%s",root,names[i]); int fd=open(b,O_CREAT|O_WRONLY,0644); if(fd>=0)close(fd); }
    snprintf(b,sizeof b,"%s/sub",root); mkdir(b,0755);

    int dfd = open(root, O_RDONLY|O_DIRECTORY);
    struct dirent **nl;
    int n = scandirat(dfd, ".", &nl, only_txt, alphasort);
    printf("n=%d\n", n);
    for(int i=0;i<n;i++){ printf("  %s\n", nl[i]->d_name); free(nl[i]); }
    free(nl);
    /* all entries, sorted */
    int n2 = scandirat(dfd, ".", &nl, NULL, alphasort);
    printf("all=%d:", n2);
    for(int i=0;i<n2;i++){ printf(" %s", nl[i]->d_name); free(nl[i]); }
    printf("\n"); free(nl);
    /* error: nonexistent */
    printf("missing=%d\n", scandirat(dfd, "nope", &nl, NULL, NULL));
    close(dfd);
    snprintf(b,sizeof b,"rm -rf '%s'",root); if(system(b)){}
    return 0;
}
