# Open tasks & deferred work

Single source of truth for things that need revisiting. Update on
every PR that opens, closes, or pivots an item. Tag closed items
with their merging PR and date.

## Open — actively worked

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

F244 narrowed the remaining gap to **openssh privsep monitor↔
preauth AF_UNIX socketpair**. `sshd -ddd` trace shows monitor
sends `mm_request_send: entering, type 105` (the PAM init reply)
and preauth's `mm_request_receive_expect: entering, type 105` is
waiting — but preauth never receives. Message lost on the
AF_UNIX socketpair across the privsep boundary.

Next: audit our `crates/kernel/net/src/unix_sock.rs`
`UnixPair`/`UnixEnd` send + recv path — likely a missed wakeup
for the cross-process recv side. `/etc/pam.d/sshd` stays on
`pam_permit` until this unblocks.

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
