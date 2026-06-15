/* utmp/utmpx login-record DB vs host glibc. Use a private temp path via
   utmpname() for determinism (host /var/run/utmp varies run-to-run); write
   crafted records with pututline, rewind, read back with getutent/getutline/
   getutid, print stable fields. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <utmp.h>

#define PATH "/tmp/oxide_utmp_test_t_utmp"

static void mk(struct utmp *u, short type, int pid, const char *id,
               const char *line, const char *user){
    memset(u, 0, sizeof *u);
    u->ut_type = type;
    u->ut_pid = pid;
    strncpy(u->ut_id, id, sizeof u->ut_id);
    strncpy(u->ut_line, line, sizeof u->ut_line);
    strncpy(u->ut_user, user, sizeof u->ut_user);
}

int main(void){
    unlink(PATH);
    utmpname(PATH);

    struct utmp a, b, c;
    mk(&a, USER_PROCESS, 101, "t1", "tty1", "alice");
    mk(&b, USER_PROCESS, 202, "t2", "tty2", "bob");
    mk(&c, LOGIN_PROCESS, 303, "t3", "tty3", "carol");

    setutent();
    pututline(&a);
    pututline(&b);
    pututline(&c);
    endutent();

    /* sequential read-back */
    setutent();
    struct utmp *e;
    while ((e = getutent()) != NULL)
        printf("ent type=%d pid=%d line=%s user=%s\n",
               e->ut_type, e->ut_pid, e->ut_line, e->ut_user);
    endutent();

    /* getutline: find by ut_line */
    struct utmp q;
    memset(&q, 0, sizeof q);
    strncpy(q.ut_line, "tty2", sizeof q.ut_line);
    setutent();
    e = getutline(&q);
    printf("line tty2 -> %s pid=%d\n", e ? (char*)e->ut_user : "NULL", e ? e->ut_pid : -1);

    /* getutid: find by ut_id */
    memset(&q, 0, sizeof q);
    q.ut_type = USER_PROCESS;
    strncpy(q.ut_id, "t1", sizeof q.ut_id);
    setutent();
    e = getutid(&q);
    printf("id t1 -> %s pid=%d\n", e ? (char*)e->ut_user : "NULL", e ? e->ut_pid : -1);
    endutent();

    unlink(PATH);
    return 0;
}
