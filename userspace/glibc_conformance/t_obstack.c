/* <obstack.h> object-stack pools vs host glibc. Exercises the underlying
   exported helpers via the header macros: obstack_init -> _obstack_begin,
   grow/1grow/blank crossing a chunk boundary -> _obstack_newchunk,
   obstack_finish/object_size (inline), obstack_printf/vprintf, obstack_free,
   _obstack_memory_used / _obstack_allocated_p. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <obstack.h>

#define obstack_chunk_alloc malloc
#define obstack_chunk_free  free

/* _obstack_allocated_p is exported by libc.so.6 but not declared in the
   public header (it backs no macro on modern glibc); declare it ourselves. */
extern int _obstack_allocated_p(struct obstack *, void *);

int main(void) {
    struct obstack ob;
    obstack_init(&ob);

    /* Build a small object with obstack_grow + a single char. */
    obstack_grow(&ob, "hello", 5);
    obstack_1grow(&ob, '!');
    obstack_grow0(&ob, "", 0);            /* NUL-terminate */
    printf("size1=%d\n", (int) obstack_object_size(&ob));
    char *o1 = (char *) obstack_finish(&ob);
    printf("obj1=%s\n", o1);

    /* Grow a big object that forces a new chunk (default chunk ~4096). */
    for (int i = 0; i < 5000; i++)
        obstack_1grow(&ob, (char) ('A' + (i % 26)));
    int big = (int) obstack_object_size(&ob);
    char *o2 = (char *) obstack_finish(&ob);
    printf("size2=%d first=%c last=%c\n", big, o2[0], o2[big - 1]);
    printf("o1-still-valid=%s\n", o1);     /* finished objects never move */

    /* obstack_blank reserves uninitialized space (void macro); fill via base. */
    obstack_blank(&ob, 4);
    char *blk = (char *) obstack_base(&ob);
    memcpy(blk, "abcd", 4);
    printf("blank-size=%d\n", (int) obstack_object_size(&ob));
    char *o3 = (char *) obstack_finish(&ob);
    printf("blank=%c%c%c%c\n", o3[0], o3[1], o3[2], o3[3]);

    /* obstack_printf / obstack_vprintf into the growing object. */
    int n = obstack_printf(&ob, "x=%d y=%s z=%05d", 42, "str", 7);
    obstack_1grow(&ob, '\0');
    char *o4 = (char *) obstack_finish(&ob);
    printf("printf-ret=%d printf=%s\n", n, o4);

    /* memory_used grows with chunks; allocated_p locates a live object. */
    printf("alloc_p(o4)=%d alloc_p(NULL+stack)=%d\n",
           _obstack_allocated_p(&ob, o4),
           _obstack_allocated_p(&ob, (void *) &ob));
    printf("mem_used>0=%d\n", _obstack_memory_used(&ob) > 0);

    /* Free back to o2: o2..o4 gone, o1 region freed too if same chunk path. */
    obstack_free(&ob, o2);
    printf("after-free alloc_p(o2)=%d\n", _obstack_allocated_p(&ob, o2));

    /* Tear the whole obstack down. */
    obstack_free(&ob, NULL);
    printf("done\n");
    return 0;
}
