# Open tasks & deferred work

Single source of truth for things that need revisiting. Update on
every PR that opens, closes, or pivots an item. Tag closed items
with their merging PR and date.

## Open — actively worked

### T16 — Growable kernel heap (CRITICAL, blocks everything bigger)
Our `kalloc::KAlloc` is a fixed-size static BSS array (raised to
256 MiB in F246). Once the hole-list fragments past that or a single
large alloc exceeds the available contiguous run, the kernel panics
on alloc — even when the underlying VM has GBs of RAM free.

Real Linux uses vmalloc + the page frame allocator: each large alloc
gets backing PMM pages mapped into a kernel virtual range; small
allocs ride a slab. We need the equivalent before anything bigger
than current workloads runs reliably.

Plan:
1. Reserve a 1 GiB kernel VA range for the dynamic heap (above the
   existing static heap).
2. Add a `kalloc::grow(extra_bytes)` path that requests PMM pages,
   maps them into the reservation, and extends the hole-list.
3. On alloc-failure in the hole-list, attempt `grow(round_up(size))`
   before returning `null`.
4. Track total mapped heap pages in `/proc/meminfo` (Slab/MemAvailable).

Until T16 lands every "this works on Linux but OOMs on oxide" bug
will trace here.



### T11 — ARM TCP CLOSE_WAIT leak (high impact)
Accepted TCP sockets on ARM never reach `InetSocket::Drop` after
the peer side closes. Caps `SSH_SMOKE_CONNECTIONS=4` on ARM TCG;
cumulative SSH connections accumulate ~680 KB/each. Hunt has been
multi-hour without a smoking gun — `glue_munmap` against
`cur.mm` fix in F230 was on the right path but didn't fully close
it. Next: instrument `Arc<InetSocket>` strong-count at each fd
close to find the stray ref holder.

### T14 — Real `pam_unix.so` activation (medium impact)
F242 wired CLONE_SETTLS into `child.arch_ctx.fs_base`. F243
made `oxide_context_switch` `wrmsr` FS_BASE on the next task so
first-run pthreads start with correct TLS. `pthread_join` now
works end-to-end (`/bin/pthread_socketpair_probe` PASSes).

F244 narrowed to monitor↔preauth AF_UNIX socketpair message
loss between type 104 (request) and type 105 (response).

F245 ruled out basic AF_UNIX cross-process patterns —
/bin/socketpair_fork_probe round-trips length-prefixed messages
and works (including nonblocking + poll-with-infinite-timeout,
which exactly matches openssh's atomicio6 pattern).

F246 narrowed further: openssh's `UNSUPPORTED_POSIX_THREADS_HACK`
default means `pthread_create` is actually `fork()`. So the
sshpam_init_ctx path is a NESTED fork (monitor forks the
fake-pthread child while preauth is waiting on type 105 reply).
Pam_permit works because its `.so` is `-nostdlib` (no
DT_NEEDED) — pam_unix.so has DT_NEEDED libc.so, triggering
nested dlopen during PAM init. The difference between
working/hanging seems to be the nested dlopen side-effects
during fork, not the AF_UNIX path itself.

Next: build a minimal pam_unix variant with `-nostdlib` (just
the symbol exports + a hard-coded fail/success) — if that
works, the libc-load is the trigger. Then audit our
fork/dlopen interaction (likely an mmap or ld-musl reentry
issue under fork).

### T15 — ARM dynamic bash as `/bin/sh` boot wedge (low impact)
Staging dynamic bash at `/bin/sh` on ARM wedges init silently
post-keymap. Bash dynamically loads fine when invoked as
`/bin/bash` explicitly. Likely an ARM-specific kernel-side
edge in our dynamic-exec path during init. Workaround: keep
busybox-ash as `/bin/sh` on ARM.

## Recently closed

- **T13 SSH-connect smoke through PAM dlopen** — closed by **#1314 F231** (real PAM dlopen via dynamic sshd + pam_permit.so).
- **T12 wait4 status decode `$?=255`** — closed by **#1320 F237** (clear SIGCHLD pending bit when wait4 drains last zombie).
- **T10 multi-conn ssh smoke** — closed earlier (boot-smoke-ssh.sh tail-tools + pty).

## Notes for the next session

- The kernel-side investigation paths are tracked in `state.md`
  (which is short-lived). The DURABLE work queue lives here.
- When opening a new branch, add an entry here; when closing,
  move it to the "Recently closed" section with the merging PR.
- If a task has a multi-step plan, add a `Plan` sub-list under it.
