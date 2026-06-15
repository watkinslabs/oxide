/* fs/mem/vector syscall-wrapper audit vs host glibc (docs/59§7). DETERMINISTIC,
   non-root: every printed value is fixed (sizes, flags, return codes, stat type
   bits) — random/path-suffix bytes are never printed, only their effect. Real
   syscalls on temp files; the harness runs our libc against the host kernel.
   Cleans up all temp files / dirs / fifos. Avoids mount/umount (need root). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/random.h>

int main(void){
    /* 1. ftruncate64 + fstat size round-trip. */
    char fpath[] = "/tmp/oxide_fssys_XXXXXX";
    int fd = mkstemp(fpath);
    if(fd < 0){ printf("mkstemp-fail\n"); return 1; }
    int tr = ftruncate64(fd, 4096);
    struct stat st;
    fstat(fd, &st);
    printf("ftruncate64=%d fstat_size=%lld isreg=%d\n",
           tr, (long long)st.st_size, S_ISREG(st.st_mode)!=0);

    /* 2. writev / readv 2-iovec round-trip. */
    struct iovec wv[2];
    wv[0].iov_base = "hello "; wv[0].iov_len = 6;
    wv[1].iov_base = "world";  wv[1].iov_len = 5;
    lseek(fd, 0, SEEK_SET);
    ssize_t wn = writev(fd, wv, 2);
    char b0[6], b1[5];
    struct iovec rv[2];
    rv[0].iov_base = b0; rv[0].iov_len = 6;
    rv[1].iov_base = b1; rv[1].iov_len = 5;
    lseek(fd, 0, SEEK_SET);
    ssize_t rn = readv(fd, rv, 2);
    printf("writev=%zd readv=%zd match=%d\n", wn, rn,
           memcmp(b0,"hello ",6)==0 && memcmp(b1,"world",5)==0);

    /* 3. fcntl F_GETFL / F_SETFL O_NONBLOCK round-trip. */
    int fl = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    int fl2 = fcntl(fd, F_GETFL);
    printf("nonblock_before=%d nonblock_after=%d\n",
           (fl & O_NONBLOCK)!=0, (fl2 & O_NONBLOCK)!=0);
    close(fd);
    unlink(fpath);

    /* 4. mkdtemp -> stat the dir. */
    char dpath[] = "/tmp/oxide_fsdir_XXXXXX";
    char *dp = mkdtemp(dpath);
    struct stat ds;
    int dr = (dp != NULL) ? stat(dpath, &ds) : -1;
    printf("mkdtemp_ok=%d isdir=%d stat=%d\n",
           dp!=NULL, (dp!=NULL && S_ISDIR(ds.st_mode))!=0, dr);
    if(dp) rmdir(dpath);

    /* 5. getrandom fills a buffer (check returned length, not the bytes). */
    unsigned char rb[32];
    ssize_t gr = getrandom(rb, sizeof rb, 0);
    printf("getrandom_len=%zd\n", gr);

    /* 6. madvise(MADV_NORMAL) on an anonymous mmap returns 0. */
    void *m = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    int ma = (m != MAP_FAILED) ? madvise(m, 4096, MADV_NORMAL) : -1;
    printf("mmap_ok=%d madvise=%d\n", m!=MAP_FAILED, ma);
    if(m != MAP_FAILED) munmap(m, 4096);

    /* 7. mkfifo -> stat S_ISFIFO. */
    char fifo[] = "/tmp/oxide_fsfifo_test";
    unlink(fifo);
    int mf = mkfifo(fifo, 0600);
    struct stat fs;
    int fst = (mf==0) ? stat(fifo, &fs) : -1;
    printf("mkfifo=%d isfifo=%d\n", mf, (mf==0 && S_ISFIFO(fs.st_mode))!=0);
    unlink(fifo);

    return 0;
}
