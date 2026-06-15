/* Misc process/identity/dir/temp + utmp _r vs host glibc. Everything here is
   made deterministic: cwd ops run in a known chdir'd tmp dir; the symlink for
   canonicalize_file_name is created fresh; tmpnam/tempnam are checked only by
   their /tmp prefix (the volatile suffix is not printed); putpwent is written
   to a tmpfile and read back; on_exit prints in a forked child; wait3 returns
   the child's pid+status; getutent_r reads back a record written via a private
   utmpname() path. Volatile parts (pid in wait3, the temp suffix) are NOT
   printed — only stable shape is. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/resource.h>
#include <utmp.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#define DIR  "/tmp/oxide_procmisc_dir"
#define LINK "/tmp/oxide_procmisc_dir/lnk"
#define TGT  "/tmp/oxide_procmisc_dir/target"
#define UTPATH "/tmp/oxide_procmisc_utmp"

static void child_handler(int status, void *arg){
    printf("on_exit status=%d arg=%ld\n", status, (long)(intptr_t)arg);
    fflush(stdout);
}

int main(void){
    /* ---- getwd / get_current_dir_name in a known dir ---- */
    rmdir(DIR); mkdir(DIR, 0777);
    chdir(DIR);
    char wd[PATH_MAX];
    char *g = getwd(wd);
    printf("getwd=%s\n", g ? g : "NULL");
    char *cd = get_current_dir_name();
    printf("getcwd_name=%s\n", cd ? cd : "NULL");
    free(cd);

    /* ---- canonicalize_file_name on a fresh symlink ---- */
    int fd = open(TGT, O_CREAT|O_WRONLY, 0644); if (fd >= 0) close(fd);
    unlink(LINK); symlink(TGT, LINK);
    char *can = canonicalize_file_name(LINK);
    printf("canon=%s\n", can ? can : "NULL");
    free(can);

    /* ---- tmpnam / tempnam: prefix check only ---- */
    char tn[L_tmpnam];
    char *t = tmpnam(tn);
    printf("tmpnam_prefix=%d\n", t && strncmp(t, "/tmp/", 5) == 0);
    char *tp = tempnam(NULL, "pfx");
    printf("tempnam_prefix=%d has_pfx=%d\n",
           tp && strncmp(tp, "/tmp/", 5) == 0,
           tp && strstr(tp, "pfx") != NULL);
    free(tp);

    /* ---- remove a file then a dir ---- */
    int rf = open("/tmp/oxide_procmisc_dir/f", O_CREAT|O_WRONLY, 0644); if (rf>=0) close(rf);
    printf("remove_file=%d\n", remove("/tmp/oxide_procmisc_dir/f"));
    mkdir("/tmp/oxide_procmisc_dir/sub", 0777);
    printf("remove_dir=%d\n", remove("/tmp/oxide_procmisc_dir/sub"));

    /* ---- putpwent to a tmpfile, read back ---- */
    {
        struct passwd p;
        p.pw_name = "joe"; p.pw_passwd = "x"; p.pw_uid = 4242; p.pw_gid = 99;
        p.pw_gecos = "Joe T"; p.pw_dir = "/home/joe"; p.pw_shell = "/bin/sh";
        FILE *f = fopen("/tmp/oxide_procmisc_pw", "w+");
        putpwent(&p, f);
        rewind(f);
        char line[256]; line[0]=0;
        if (fgets(line, sizeof line, f)) printf("putpwent=%s", line);
        fclose(f);
        unlink("/tmp/oxide_procmisc_pw");
    }

    /* ---- on_exit handler in a forked child + wait3 status ---- */
    {
        fflush(stdout); /* drain buffered output so the child doesn't re-flush it */
        pid_t pid = fork();
        if (pid == 0) {
            on_exit(child_handler, (void*)(intptr_t)7);
            exit(3);
        }
        int status = 0;
        struct rusage ru;
        pid_t w = wait3(&status, 0, &ru);
        printf("wait3_ok=%d exited=%d code=%d\n",
               w == pid, WIFEXITED(status), WEXITSTATUS(status));
    }

    /* ---- getutent_r over a private utmp path ---- */
    {
        unlink(UTPATH);
        utmpname(UTPATH);
        struct utmp a;
        memset(&a, 0, sizeof a);
        a.ut_type = USER_PROCESS; a.ut_pid = 555;
        strncpy(a.ut_id, "z1", sizeof a.ut_id);
        strncpy(a.ut_line, "ttyz", sizeof a.ut_line);
        strncpy(a.ut_user, "zoe", sizeof a.ut_user);
        setutent(); pututline(&a); endutent();

        setutent();
        struct utmp buf, *res;
        int r = getutent_r(&buf, &res);
        printf("getutent_r=%d type=%d pid=%d user=%s\n",
               r, res ? res->ut_type : -1, res ? res->ut_pid : -1,
               res ? (char*)res->ut_user : "NULL");
        endutent();
        unlink(UTPATH);
    }

    /* ---- cleanup ---- */
    unlink(LINK); unlink(TGT); rmdir(DIR);
    return 0;
}
