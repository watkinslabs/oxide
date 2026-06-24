/* passwd/group/shadow enumeration + reentrant + string parsers vs host glibc.
 * Determinism: drive the fget/sget string parsers over FIXED inline data in
 * temp files, never the host live /etc/passwd. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <shadow.h>

static const char *PW =
    "root:x:0:0:root:/root:/bin/bash\n"
    "alice:x:1000:1000:Alice A:/home/alice:/bin/sh\n"
    "bob:y:1001:1001:Bob B:/home/bob:/usr/bin/zsh\n";

static const char *GR =
    "root:x:0:\n"
    "wheel:x:10:alice,bob\n"
    "users:x:100:alice\n";

static void write_tmp(char *path, const char *data) {
    strcpy(path, "/tmp/t_pwgr_XXXXXX");
    int fd = mkstemp(path);
    if (fd < 0) { perror("mkstemp"); exit(1); }
    FILE *f = fdopen(fd, "w");
    fputs(data, f);
    fclose(f);
}

int main(void) {
    char pwpath[64], grpath[64];
    write_tmp(pwpath, PW);
    write_tmp(grpath, GR);

    /* --- fgetpwent over crafted passwd lines --- */
    FILE *pf = fopen(pwpath, "r");
    struct passwd *p;
    while ((p = fgetpwent(pf)) != NULL)
        printf("pw %s:%u:%u:%s:%s\n", p->pw_name, p->pw_uid, p->pw_gid, p->pw_dir, p->pw_shell);
    fclose(pf);

    /* --- fgetgrent over crafted group lines (incl. multi-member) --- */
    FILE *gf = fopen(grpath, "r");
    struct group *g;
    while ((g = fgetgrent(gf)) != NULL) {
        printf("gr %s:%u:", g->gr_name, g->gr_gid);
        for (char **m = g->gr_mem; *m; m++) printf("%s%s", m == g->gr_mem ? "" : ",", *m);
        printf("\n");
    }
    fclose(gf);

    /* --- sgetspent: parse one shadow string --- */
    struct spwd *s = sgetspent("user:$6$salt$hash:19000:0:99999:7:::");
    printf("sp %s:%s:%ld:%ld:%ld:%ld:%ld:%ld\n",
           s->sp_namp, s->sp_pwdp, s->sp_lstchg, s->sp_min, s->sp_max,
           s->sp_warn, s->sp_inact, s->sp_expire);

    /* --- fgetpwent_r: reentrant over the same temp file --- */
    FILE *pf2 = fopen(pwpath, "r");
    struct passwd pe; char pbuf[512]; struct passwd *pr;
    while (fgetpwent_r(pf2, &pe, pbuf, sizeof pbuf, &pr) == 0 && pr)
        printf("pwr %s:%u\n", pr->pw_name, pr->pw_uid);
    fclose(pf2);

    /* --- fgetgrent_r --- */
    FILE *gf2 = fopen(grpath, "r");
    struct group ge; char gbuf[512]; struct group *gr;
    while (fgetgrent_r(gf2, &ge, gbuf, sizeof gbuf, &gr) == 0 && gr) {
        printf("grr %s:%u:", gr->gr_name, gr->gr_gid);
        for (char **m = gr->gr_mem; *m; m++) printf("%s%s", m == gr->gr_mem ? "" : ",", *m);
        printf("\n");
    }
    fclose(gf2);

    /* --- sgetspent_r --- */
    struct spwd se; char sbuf[256]; struct spwd *sr;
    int rc = sgetspent_r("carol:!:18000:0:99999:7:30:20000:", &se, sbuf, sizeof sbuf, &sr);
    printf("spr rc=%d %s:%s:%ld:%ld\n", rc, sr->sp_namp, sr->sp_pwdp, sr->sp_lstchg, sr->sp_expire);

    /* --- ERANGE path: tiny buffer to fgetpwent_r --- */
    FILE *pf3 = fopen(pwpath, "r");
    struct passwd pe2; char tiny[4]; struct passwd *pr2;
    int erc = fgetpwent_r(pf3, &pe2, tiny, sizeof tiny, &pr2);
    printf("erange rc=%d result_null=%d\n", erc != 0, pr2 == NULL);
    fclose(pf3);

    /* --- getpw: obsolete passwd line renderer over the live passwd DB --- */
    char gb[4096];
    int grc = getpw(getuid(), gb);
    printf("getpw self rc=%d line=%s\n", grc, grc == 0 ? gb : "-");
    int gmiss = getpw((uid_t)4294967294u, gb);
    printf("getpw miss=%d\n", gmiss);

    unlink(pwpath);
    unlink(grpath);
    return 0;
}
