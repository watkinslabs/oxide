/* SysV semaphores + POSIX named sem + POSIX shm vs host glibc.
 * Deterministic, non-root: never prints kernel-assigned ids (they vary per
 * run) — only success flags, GETVAL counts, and return codes. Cleans up every
 * IPC object it creates. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/sem.h>
#include <sys/mman.h>
#include <semaphore.h>
#include <errno.h>
#include <time.h>

int main(void){
    /* --- SysV semaphore set --- */
    int sid = semget(IPC_PRIVATE, 1, IPC_CREAT | 0600);
    printf("semget>=0=%d\n", sid >= 0);
    int r = semctl(sid, 0, SETVAL, 3);
    printf("setval=%d getval=%d\n", r, semctl(sid, 0, GETVAL));
    struct sembuf sb = { 0, -1, 0 };          /* down by 1 */
    printf("semop=%d getval=%d\n", semop(sid, &sb, 1), semctl(sid, 0, GETVAL));
    printf("rmid=%d\n", semctl(sid, 0, IPC_RMID));

    /* --- POSIX shared memory --- */
    shm_unlink("/oxide_test_shm");            /* clean any stale object */
    int fd = shm_open("/oxide_test_shm", O_CREAT | O_RDWR, 0600);
    printf("shm_open>=0=%d\n", fd >= 0);
    printf("ftrunc=%d\n", ftruncate(fd, 4096));
    int *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    printf("mmap_ok=%d\n", p != MAP_FAILED);
    *p = 0xCAFE;
    printf("shm_val=%d\n", *p);
    printf("munmap=%d\n", munmap(p, 4096));
    close(fd);
    printf("shm_unlink=%d\n", shm_unlink("/oxide_test_shm"));

    /* --- POSIX named semaphore --- */
    sem_unlink("/oxide_test_sem");            /* clean any stale object */
    sem_t *s = sem_open("/oxide_test_sem", O_CREAT, 0600, 1);
    printf("sem_open_ok=%d\n", s != SEM_FAILED);
    printf("sem_wait=%d\n", sem_wait(s));
    int v = -1; sem_getvalue(s, &v);
    printf("getvalue=%d\n", v);
    printf("sem_post=%d\n", sem_post(s));
    sem_t local;
    sem_init(&local, 0, 0);
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_nsec += 1000000;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_nsec -= 1000000000L; ts.tv_sec++; }
    errno = 0;
    int cw = sem_clockwait(&local, CLOCK_MONOTONIC, &ts);
    printf("sem_clockwait_timeout=%d errno=%d\n", cw, errno == ETIMEDOUT);
    sem_destroy(&local);
    printf("sem_close=%d\n", sem_close(s));
    printf("sem_unlink=%d\n", sem_unlink("/oxide_test_sem"));
    return 0;
}
