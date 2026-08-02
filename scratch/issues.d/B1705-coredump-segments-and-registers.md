# B1705 — a core dump that carries memory and a crash site

Branch `B1705-coredump-segments-and-registers`, off `origin/main` at `5fa6cdf5a`.

The assembler, the notes, `core_pattern`, the pipe/file destinations, the filter
and the selection ladder all existed. Nothing connected them: the builder was
handed `segments: &[]` and a zero-filled register block, so every dump written
was notes and nothing else, whatever `/proc/<pid>/coredump_filter` said.

This lane wires the two inputs and proves the result in the guest.

## Closed

| Row | Was | Now |
|---|---|---|
| 283 (high) | `write_for_current` passes an empty mapping list and a zero register block | The selection ladder runs over `mm.snapshot_vmas()`; the register block comes from the thread's own entry frame, threaded in from the return path that tears the process down |
| 289 (high) | nothing calls the selection ladder; the image has no `PT_LOAD` | `coredump::plan::plan_mappings` walks the tree through `describe_vma` → `vma_dump_verdict` → `resolve_elf_probe` and yields one planned segment per mapping |
| 284 (med) | `dump_size` is invented by every caller | The walk takes it from the ladder under the mm's own filter word; no caller supplies a policy |
| 290 (low) | `process_mrelease` reads `coredumping` as always false | The mm latches a dumping flag for the length of the write and `exit_state` reads it |
| 368 (low) | the end-to-end observation was never made | `tools/guest-coredump-check.py` crashes a real program in the guest and compares the dumped bytes at the crashing program counter against the on-disk object |

The file destination was rebuilt on the open path (below). `NT_FILE` gained
paths as part of this: `FileBacking::map_path` (default `None`),
populated by the exec image backing and by file-backed `mmap`. Without it the
table was empty and a debugger had nothing to reopen for the pages a dump does
not carry.

## The file destination now opens instead of creating

The dump was being written correctly and was **unreachable by path**: the
destination created through the directory inode, which leaves any cached
negative dentry for that name in place, so the file sat in the directory, a
listing showed it, and every lookup reported ENOENT.

```
-?????????  ? ?    ?    ?            ? core        <- readdir sees it
ls: cannot access '/tmp/coredump-check/core': No such file or directory
```

The first fix patched the cache after the create, copying what this tree's
`openat` does. That was wrong and is not what shipped: the reference kernel
never creates a core file through a directory inode at all — it opens the path
under the dying process's credentials and writes through the open description,
and the cache is maintained inside that path because creating and publishing
are one operation there.

So this lane built what was missing rather than working around its absence:

| New | What it owns |
|---|---|
| `vfs::vfs_create_at` | permission gate + the exclusive parent lock + backend create + cache publication + notification, as ONE operation. `openat`'s create arm now calls it instead of open-coding the sequence. |
| `vfs::file::open_file_at` | everything an open does to reach a live `File`, with no descriptor: split out of `install_open_at` so an in-kernel open and a descriptor open cannot diverge. |
| `vfs::file::kernel_open_at_root` | the in-kernel open this tree had no equivalent of. Resolves under a supplied root, creates the leaf on `O_CREAT`, never follows the final component. |

`coredump::file_target` is now: open with `O_CREAT|O_RDWR|O_NOFOLLOW`
(`O_EXCL` when the dump's dumpability was downgraded, which replaces the
unlink-first step this had invented), run the ladder on what was actually
opened, truncate, write through the `File`.

The ladder gained the two rungs that only became checkable once there was a
real open description behind it: the name is still hashed (not unlinked or
renamed out from under the open), and the description can be written through.

## Evidence

Hosted: `cargo test -p fs --lib` 919 → 935. Positive controls, each defect
reinstated alone and then restored (baseline 142 coredump tests green):

| Defect reinstated | Result |
|---|---|
| builder gets an empty mapping list | 9 failed |
| zero-filled register block | 4 failed |
| mappings name no object | 2 failed |
| the deferred verdict never reads memory | 1 failed |
| arm float block keeps the save-area word order | 1 failed |
| restored | 142 passed |

`make hosted-gate` PASS (103 crates), `make feature-gate` clean on both arches,
`make lint-ratchet` PASS — at baseline (1766).

## Left open, with the reason

| Row | Why it stays |
|---|---|
| 285 `NT_X86_XSTATE` | Deliberately absent. `NT_PRFPREG` is now emitted (the legacy save area, which is well defined whatever wider format the machine saves in); an `xsave` header whose `xstate_bv`/`xcomp_bv` this lane cannot vouch for would make gdb decode garbage, which is worse than the note's absence. |
| 286 `NT_FILE` has no device or inode | The format has no room for them. Faithful, not a defect. |
| 287 an unreadable mapping is written as zeroes | Faithful: the reference turns a skipped range into a file hole too. |
| 291 the `@` socket destination delivers nothing | Needs a kernel-side connect to an `AF_UNIX` listener, which is a socket-layer lane, not a dump-image one. Unchanged. |
| 292 the file destination resolves from the crashing namespace root | Unchanged; a destination-policy question, not an image one. |
| 314 vDSO always-dump keys on one segment | Still address-keyed. The right shape is a `VmaFlags` bit set by `vdso::map_into_current` on the vvar page and on every `PT_LOAD` it maps, which would drop the address heuristic entirely and cover any number of segments — it changes `describe_vma`'s signature and every case in `tests/selection.rs`, so it belongs in its own lane. The vDSO this port ships has one loadable segment, so nothing is lost today. |
| 93 the boundary page of a `.bss`-bearing `PT_LOAD` | An exec-loader layout question (`exec::layout::split` runs before the new address space is active), not a dump one. The dump carries whatever the loader mapped. |
| 367 a private file mapping never acquires an `anon_vma` | Real, and it costs a crashed program's modified `.data` under the default filter. Fixing it means the private write-fault path calling the equivalent of `anon_vma_prepare`, which needs mutable VMA access under a write lock in the fault path — an mm-lane change with its own risk, not a dump-image one. Worked around here only in the sense that the guest check sets `0x3f`, which carries the whole mapping by the file-backed rule instead. |

## Also fixed on the way

`/proc/<pid>/coredump_filter` could be read but never written from a shell:
`echo 0x3f > /proc/self/coredump_filter` reported "Read-only file system". A
shell redirection opens with `O_TRUNC`, and the default `InodeOps::truncate`
on a procfs leaf returns `Erofs`. The file now carries the same no-op
`truncate` the writable sysctl leaves already use, so the filter that decides
which mappings a dump contains is settable by the documented means.

Its own `#[cfg(test)] mod tests` has never run: `cargo test -p procfs --lib`
does not compile, because `coredump_filter.rs` calls `sched::live::registry`,
which is configured out of the hosted build. Pre-existing, not introduced here,
but it means every case in that module is unverified.

## Found on the way, NOT fixed — the ptrace x86 saved-frame offsets are stale

`101_ptrace/frame.rs` reads the tracee's frame as **16 quadwords at
`kernel_stack - 0x80`**. Every x86 entry has saved a **22-quadword `PtRegs` at
`kernel_stack - 0xb0`** since `83828711b`: `current_pt_regs()` is
`percpu_syscall_kstack() - PT_REGS_BYTES`, and `switch.rs` stores
`task.kernel_stack` into that per-CPU slot, so both derive from the same top.

The ptrace base is therefore 0x30 bytes into the frame, and its field indexes
do not describe what is there: `F_ORIG_RAX` (index 0) lands on `r11`, `F_RDI`
on `r10`, `F_RIP` on `rcx`, `F_R12` (index 15) on `ss`. `PTRACE_GETREGS`,
`GETREGSET(NT_PRSTATUS)`, `PEEKUSER` and every `SET*` counterpart are affected;
`regs/tests.rs` cannot see it because it tests the array mapping against a
synthetic array, not against the frame the kernel actually saves.

aarch64 is correct (`SvcFrame` is 0x120 bytes and the ptrace base matches).

Not fixed here: it is a different subsystem's contract and wants its own lane
plus a test that pins the offsets against `PT_REGS_BYTES` rather than against a
literal. This lane deliberately did NOT reuse that mapping — the dump's register
block is built from `PtRegs`/`SvcFrame` directly, which is why it is right.

## Notes for the next lane

- `tools/guest-coredump-check.py` boots with `debug-boot` off. With it on, the
  `[INOTIFY-ENOENT …]` klog stream drowns every command's output on the serial
  line — the same thing that made the earlier lane's `/proc/self/maps` probe
  inconclusive.
- `make qemu-<arch>` leaves QEMU running when its `make` is terminated, holding
  a write lock on `target/builds/default/root-<arch>.img`; every later run then
  dies with `Failed to get "write" lock` and no kernel output. The check script
  kills it through `target/builds/default/qemu-<arch>.pid`.
- A wedged 2.5-hour-old `qemu-system-x86_64` from the `b1700-nm` build namespace
  was running on this box throughout, holding gdb port 51515. Not this lane's,
  not reaped by it.
