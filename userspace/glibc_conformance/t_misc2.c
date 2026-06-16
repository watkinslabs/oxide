/* chroot(EPERM unpriv), getdtablesize (>0), shmget/shmat/shmdt round-trip. */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/shm.h>
#include <string.h>

int main(void) {
    printf("getdtablesize_pos=%d\n", getdtablesize() > 0);

    /* chroot unprivileged → -1/EPERM (deterministic for a normal uid) */
    int r = chroot("/nonexistent-xyz");
    printf("chroot=%d eperm=%d\n", r, (r < 0 && errno == EPERM) ? 1 : 0);

    /* SysV shm: create, attach, write, detach, remove */
    int id = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
    if (id < 0) { printf("shmget fail\n"); return 0; }
    char *p = (char*)shmat(id, NULL, 0);
    int ok = (p != (char*)-1);
    if (ok) { p[0] = 42; ok = (p[0] == 42); shmdt(p); }
    shmctl(id, IPC_RMID, NULL);
    printf("shm_ok=%d\n", ok);
    return 0;
}
