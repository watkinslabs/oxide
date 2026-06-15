/* scandir vs host glibc over a temp dir (alphasort → deterministic order). */
#define _GNU_SOURCE
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static int only_txt(const struct dirent *e){
    size_t n = strlen(e->d_name);
    return n >= 4 && strcmp(e->d_name + n - 4, ".txt") == 0;
}

int main(void){
    const char *root = "/tmp/oxide_scandir_test";
    mkdir(root, 0755);
    char p[256];
    const char *names[] = {"zeta.txt","alpha.txt","mid.dat","beta.txt"};
    for (int i=0;i<4;i++){ snprintf(p,sizeof p,"%s/%s",root,names[i]); close(creat(p,0644)); }

    struct dirent **list;
    int n = scandir(root, &list, NULL, alphasort);
    printf("all n=%d:", n);
    for (int i=0;i<n;i++){ printf(" %s", list[i]->d_name); free(list[i]); }
    printf("\n");
    free(list);

    n = scandir(root, &list, only_txt, alphasort);
    printf("txt n=%d:", n);
    for (int i=0;i<n;i++){ printf(" %s", list[i]->d_name); free(list[i]); }
    printf("\n");
    free(list);

    for (int i=0;i<4;i++){ snprintf(p,sizeof p,"%s/%s",root,names[i]); unlink(p); }
    rmdir(root);
    return 0;
}
