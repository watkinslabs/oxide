# state.md — session hand-off

Main `6ff6524c9`, clean: 0 open PRs, 0 worktrees, both arches boot.
**Read `scratch/LINUX-COMPLIANCE.md` first** — consolidated entry point.

## Start here: the live issue, one experiment from an answer

User's own boots show, adjacent and repeatedly:

```
[NAMEI] openat-create path="/var/log/journal/<id>/user-1000.journal" err=5
[B288 dgram /run/systemd/journal/socket pid=4451] MESSAGE=Failed to dispatch fd source: Invalid argument
```

Traced to ONE line. `ext4/rootfs/inode/special.rs::create` propagates every
error correctly except its last:

```rust
d.st.forget_created_ino(ino);
d.st.wrap_file(ino).ok_or(VfsError::Eio)   // <- err=5
```

So `create_file` SUCCEEDED (inode allocated on disk) and `wrap_file` returned
`None`. `wrap_file` has two `None` arms:

- `!inode.is_reg()` — **RULED OUT** by source: `ialloc/create.rs:34` writes
  `S_IFREG | (mode_perm & 0x0FFF)`.
- `read_inode(ino).ok()?` — **this is it.** `create_file` runs in `create_op`,
  which defers the batch commit; `forget_created_ino` then drops the page cache
  and `iforget`s the number; `read_inode` therefore goes to disk for an
  inode-table block whose write may still be pending.

**Do NOT "just commit before the forget".** `create_op` already ends with
`maybe_commit_batch()`, and the mount has a shadow reads are meant to consult.
Forcing a per-create commit papers over the real question AND reintroduces
per-operation synchronous journal commits — measured previously at ~87/s
dominating boot. The fix is probably in the read path.

Every failure also strands an allocated on-disk inode with no VFS reference — a
leak, so a retrying journald burns one per attempt.

**Also unresolved:** the "Failed to dispatch fd source" message is emitted by
the process writing to the journal socket, so it is probably journald's, NOT
gnome-shell's. An earlier theory blamed a DRM fd returning EOF; that never
explained the errno (EOF does not produce EINVAL). Confirm the emitting pid
before assuming the compositor.

## State

| | Session start | Now |
|---|---|---|
| Syscalls unaudited | 198 | **0** |
| Syscalls `IMPL` | 44 | **165** (of 385 rows) |
| `PARTIAL` | 118 | 193 → **162 real gaps, ~40 root causes** |
| Subsystem audits | none | 4, ~689 findings, **14/14 blockers closed** |
| Guest differential | 29 records | **109, exact vs host Linux, both arches** |
| GNOME | never booted | **greeter renders**, then freezes |

**The goal is not met.** The audit is complete; the implementation is not.

## Next work, ordered (detail in `scratch/partial-surface-2026-07-28.md` §4)

1. **`wrap_file` read path** — above. Cheapest, and it is the live issue.
2. **kuid/kgid translation** (16 rows) — translator exists with 2 callers.
   Needs a `Cred` type split so mixing a namespace-relative id with a stored one
   is a compile error, as Linux's `kuid_t` does. Largest single root cause.
3. **RT throttling** — no `rt_runtime`/`rt_period`/`rt_time` anywhere. Needs
   per-rq accounting + period timer. Throttling wrong wedges a boot.
   (FIFO non-preemption and the RR quantum are DONE, `B1490`.)
4. **aio ring** — `aio_context_t` is a small integer libaio dereferences;
   fio/PostgreSQL SIGSEGV rather than degrade.
5. **blocking reads** — inotify/fanotify. Wake source exists (`B1489`);
   **parking wedged the boot** — a producer does not reach `enqueue_event`.
   Find it before writing the park. `timerfd` already parks; not in this set.
6. ptrace · 7. io_uring · 8. **IF=0 campaign** — x86_64 runs syscalls
   (`IA32_FMASK`) and faults at IF=0 end to end where Linux enables interrupts;
   only three `IrqGate::save_enable()` sites exist. A campaign, not a PR.

## Hazards that each cost real hours

1. **Hosted tests cannot see stack depth; boots cannot see host-cfg builds.**
   Three arm64 stack overflows were green in every hosted test, caught only by
   `boot-smoke` as `[BADSTACK]`; a host-target build break passed every gate.
2. **Adding a sleep where no wake source exists turns a spin into a hang** —
   did this to inotify, boot went 52s → wedged at 500s.
3. **`SMOKE_KEEP_LOG` keeps only the LAST attempt** while a panic lands in the
   *failing* one. Use `SMOKE_KEEP_LOG_DIR`. Nearly caused a false retraction.
4. **Do not mark on a process name** — unmeasurable if it writes nothing to
   serial. Use the sysrq task dump, or `systemd.debug_shell=ttyS0` + `ps`.
5. **A weak implementation passes a naive test.** `AT_RANDOM`'s "two execs
   differ" passed with a clock-derived value; `pidfd_getfd`'s first test passed
   vacuously because a fresh `Task` has all capabilities. Always include the
   negative/positive control that can actually fail.
6. **Gated files hide their own tests.** `#[cfg(target_os = "oxide-kernel")]`
   compiles `#[cfg(test)] mod tests` out **silently** while cargo prints "ok" —
   six shipped instances. Put decision logic in ungated modules.
7. **An 8-byte-wrong ioctl size made a whole subsystem unreachable** — DRM
   atomic modesetting was fully implemented and had never once run.

## The one structural fact

**The dominant defect class is machinery with no callers, not missing code.**
Confirmed: ext4's orphan list (complete, wired only to `O_TMPFILE`),
`timer_slack_ns` (present, prctl-settable, read by nothing — most of a 100 ms
latency floor), `update_rtt` (TCP RTO stuck at 1 s), `atime_needs_update`,
`graft_mount`'s flags word (hardcoded 0, so every mount read "unrestricted"
from a word nothing wrote), DRM `object_type`, a second dead copy of
`get_obj_properties`, the LRU aging functions, PSI, readahead, the slab
allocator, and per-task fault counters `acct` never read.

**Grep call sites, not definitions.** Many "missing features" are wiring, and
every fix so far closed the syscall-shim half while leaving the subsystem half —
which is exactly why 193 rows still read PARTIAL.

## B1565 BPF handoff — 2026-07-30

Worktree: `/home/nd/oxide/kernel-B1565-bpf-token`.
Branch: `B1565-bpf-token`; remote is current through `1da8beccb`.

Validated pushed commits:

| Commit | Scope | Evidence |
|---|---|---|
| `29f4feb4b` | Mmapable array maps use one PMM-backed object for helper, syscall, interpreter, and shared mappings. | 233 security tests; x86 smoke 64s; arm smoke 86s; both release-kernel builds. |
| `1da8beccb` | Pseudo-directory entries retain real inode references; foundation for bpffs publication without a pathname registry. | `cargo test -p kernfs --lib`: 11 passed. |

Completed bpffs/object work:

- `crates/kernel/security/src/bpf/object.rs`: `pin` and `get` work functions.
  They validate the resolved inode's BPF filesystem magic and use the parent
  `kernfs::PseudoDir` as the only namespace owner. They retain the exact
  fd-backed inode; no BPF object registry was added.
- `crates/kernel/security/src/bpf/uapi.rs`: named `obj_pin`/`obj_get` layouts
  plus a dedicated `map_get_fd_by_id` layout.
- `crates/kernel/security/src/bpf.rs`: pathname decoding preserves the common
  attribute protocol; typed `obj_pin` / `obj_get` work entry points retain the
  BPF policy in `security`.
- `crates/kernel/security/Cargo.toml` and `Cargo.lock`: add the `kernfs`
  dependency needed by the object work function.
- `crates/kernel/security/src/bpf/map.rs`: map-ID command uses its own UAPI
  layout rather than program-ID offsets.

- `crates/kernel/syscalls/src/321_bpf.rs`: kernel-only shim resolves only
  `OBJ_PIN` and `OBJ_GET`; all other commands remain in `security::bpf`.
- `crates/kernel/security/src/bpf/btf.rs`: narrow canonical BTF identity
  predicate admits BTF objects without duplicating type checks.
- Hosted coverage: bpffs-magic rejection, duplicate pin, lifetime after close,
  and non-object/invalid-access `OBJ_GET` rejection.

Validation: `cargo test -p security --lib` (235 passed); `cargo test -p kernfs
--lib` (11 passed); release-kernel builds for x86_64 and aarch64; branch-local
`make smoke-x86` and `make smoke-arm` both exited 0.
