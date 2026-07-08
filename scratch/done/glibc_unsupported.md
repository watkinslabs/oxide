# glibc — unsupported (cannot implement)

> Hard-blocked, not deferred. 34 entries.

## header-only macros and compiler builtins: 24
> Never a libc.so.6 symbol; obstack_ and sigsetjmp expand over implemented underlying symbols; alloca is a compiler builtin.

int sigsetjmp (sigjmp_buf state, int savesigs)
void obstack_blank (struct obstack *obstack-ptr, int size)
void obstack_grow (struct obstack *obstack-ptr, void *data, int size)
void obstack_grow0 (struct obstack *obstack-ptr, void *data, int size)
void obstack_1grow (struct obstack *obstack-ptr, char c)
void obstack_ptr_grow (struct obstack *obstack-ptr, void *data)
void obstack_int_grow (struct obstack *obstack-ptr, int data)
void * obstack_finish (struct obstack *obstack-ptr)
int obstack_object_size (struct obstack *obstack-ptr)
int DES_FAILED (int err)
void * obstack_alloc (struct obstack *obstack-ptr, int size)
void * obstack_copy (struct obstack *obstack-ptr, void *address, int size)
void * obstack_copy0 (struct obstack *obstack-ptr, void *address, int size)
int obstack_init (struct obstack *obstack-ptr)
int obstack_room (struct obstack *obstack-ptr)
void obstack_1grow_fast (struct obstack *obstack-ptr, char c)
void obstack_ptr_grow_fast (struct obstack *obstack-ptr, void *data)
void obstack_int_grow_fast (struct obstack *obstack-ptr, int data)
void obstack_blank_fast (struct obstack *obstack-ptr, int size)
int IFTODT (mode_t mode)
mode_t DTTOIF (int dtype)
void * alloca (size_t size)
void * obstack_base (struct obstack *obstack-ptr)
void * obstack_next_free (struct obstack *obstack-ptr)

## PowerPC builtins: 10
> __ppc_ are PowerPC-only; oxide targets x86_64 and aarch64.

uint64_t __ppc_get_timebase (void)
uint64_t __ppc_get_timebase_freq (void)
void __ppc_yield (void)
void __ppc_mdoio (void)
void __ppc_mdoom (void)
void __ppc_set_ppr_med (void)
void __ppc_set_ppr_low (void)
void __ppc_set_ppr_med_low (void)
void __ppc_set_ppr_very_low (void)
void __ppc_set_ppr_med_high (void)
