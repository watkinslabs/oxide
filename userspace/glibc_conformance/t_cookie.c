#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

/* A cookie backed by a fixed char buffer with a position, like a tiny
   in-memory file, driven entirely through the callbacks. */
struct mem { char *base; size_t len, pos; };

static ssize_t mem_read(void *c, char *buf, size_t n){
    struct mem *m = c;
    size_t avail = m->len - m->pos;
    if (n > avail) n = avail;
    memcpy(buf, m->base + m->pos, n);
    m->pos += n;
    return (ssize_t)n;
}
static ssize_t mem_write(void *c, const char *buf, size_t n){
    struct mem *m = c;
    size_t room = m->len - m->pos;
    if (n > room) n = room;
    memcpy(m->base + m->pos, buf, n);
    m->pos += n;
    return (ssize_t)n;
}
static int mem_seek(void *c, off64_t *off, int whence){
    struct mem *m = c;
    off64_t base = whence==SEEK_CUR ? (off64_t)m->pos : whence==SEEK_END ? (off64_t)m->len : 0;
    off64_t np = base + *off;
    if (np < 0 || np > (off64_t)m->len) return -1;
    m->pos = (size_t)np;
    *off = np;
    return 0;
}
static int mem_close(void *c){ ((struct mem*)c)->pos = 999; return 0; }

int main(void){
    char store[64] = "abcdefghij";
    struct mem m = { store, 10, 0 };
    cookie_io_functions_t io = { mem_read, mem_write, mem_seek, mem_close };

    FILE *f = fopencookie(&m, "r+", io);
    char buf[16];
    size_t r = fread(buf, 1, 5, f); buf[r]=0;
    printf("read=%s pos=%ld\n", buf, ftell(f));
    fseek(f, 0, SEEK_SET);
    fputs("XYZ", f);
    fflush(f);
    printf("afterwrite store=%.10s tell=%ld\n", store, ftell(f));
    fseek(f, -3, SEEK_END);
    int c = fgetc(f);
    printf("fromend=%c\n", c);
    fclose(f);
    printf("closed_pos=%zu\n", m.pos);
    return 0;
}
