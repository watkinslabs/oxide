## Handoff: kalloc/Arc corruption hunt — fast repro found, 3 real UAFs fixed, root cause still open

### Headline
Found a ~15-25s repro of this session's long-hunted kalloc corruption bug
(vs. the ~500s live-gnome loop every prior session used): bare `debug-boot`
quickboot smoke profile (`tools/boot-smoke.sh x86`, smp=2), crash always at
`[ZRAM-SYSFS]` disksize setup. Confirmed pre-existing on clean main via A/B
(not a regression). Used it to find and fix THREE real, confirmed, reviewed
cross-CPU UAF races on `Task` fields (B1326, PR #3768, merged) — real
security/correctness bugs, independently valuable. They measurably improved
survival time (~15s -> ~500s under debug-heappoison) but did **not** fully
eliminate the corruption: a live boot still hit `kalloc invalid free` at
~504s, at the identical zram-sysfs trigger *event* (not wall-clock — same
trigger, whenever it lands). Root cause still open.

### What's fixed (B1326, merged, PR #3768)
Three `Task` fields were plain `UnsafeCell<Option<Arc<T>>>` (or
`UnsafeCell<Option<String>>`) with **zero synchronization**, read by
foreign-task syscalls with no protection against that task's own exit path
concurrently tearing the same cell down:
- **`fd_table`**: `pidfd_getfd`, `kcmp`, `/proc/<pid>/fd*` raced
  `replace_fd_table(None)` in exit paths (which runs BEFORE the Zombie
  state transition, so a caller's "not yet Zombie" check doesn't close the
  window). Traced from a live #UD Arc-refcount-overflow abort in
  `sys_close` via a 6-agent workflow (trace/verify/fix/review).
- **`mm`**: same pattern — ptrace PEEKTEXT/POKETEXT, process_madvise,
  process_mrelease, kcmp KCMP_VM, procfs smaps/pid_files/pid_stat, proclink
  all read a foreign task's `mm_ref()` raw.
- **`exe_path`**: same pattern, ~30 call sites, including
  `tick_deadline.rs` (timer-IRQ deadline scanner, walks EVERY live task on
  EVERY tick) racing `execve`'s write — a torn `String` `(ptr,len,cap)`
  read explains this session's `#PF` and "real-looking garbage" symptoms
  directly.

Fix mirrors an existing precedent (`mm_pin_lock`/`clone_mm`, already in
`task/signals.rs`): a pin-lock-and-clone pattern. Added `fd_table_pin_lock`
+ `clone_fd_table()` (new `task/fd_table.rs`, split out to stay under the
500-line cap); converted `exe_path` to `Spinlock<Option<String>,
TaskListClass>` + `exe_path()`/`with_exe_path()`/`set_exe_path()` (new
`task/exe_path.rs`). All ~40 call sites across sched/syscalls/procfs/fs/
net/ipc/console/mm-pmm updated. Both arches build clean, `pmm` 123/123,
`syscalls --lib` 160/161 (1 pre-existing unrelated failure).

**This is real, valuable, done work — do not re-investigate fd_table/mm/
exe_path.** If a future session finds another Task field with the same raw
`UnsafeCell` + foreign-task-read pattern, apply the identical pin-lock-and-
clone fix.

### What's still open — the actual root cause
Deterministic correlation: the crash fires at the zram-sysfs disksize sysfs
write, regardless of what wall-clock time that lands at (15s under bare
debug-boot, 504s under debug-heappoison's slower timing — same trigger
event both times). A parallel investigation this session (one of 3 workflow
agents) read the full zram disksize store path + uevent broadcast path
(`sysfs/src/block/zram.rs` -> `drv-zram/src/state.rs::set_disksize` ->
`state/table.rs::SlotTable::resize`, and the netlink uevent fan-out) end to
end and found it clean — no raw-pointer aliasing, no cross-CPU free-without-
lock. Its conclusion: `SlotTable::resize` is the single heaviest allocator
workout in this boot window (many page-sized `Vec`/`Box` chunk allocs), so
it's the first thing to *discover* pre-existing corruption via an unrelated
dealloc, not necessarily where the corruption is *written*.

New data point this session (bare-debug-boot sample, before all 3 fixes
above): a corrupted free-list node had `size=0x0000000000000000` — a
zeroed page-aligned pattern — and the block being freed right after it sat
exactly 4096 bytes away (one page). This is consistent with a physical page
getting zero-filled while some part of it is still (wrongly) backing
kalloc's static heap — i.e. a double-owned/double-mapped physical frame,
the exact class B1322/B1325's corruption-probe was built to catch. Wired
`probe_corruption()` into `add_free_region`'s walk-loop failure paths this
session (previously only `try_merge`/`periodic_validate` called it) — NOT
YET fired live; the sample that would have triggered it happened under
`debug-dealloc-diag` (no corruption-probe compiled in, by design — that
feature deliberately excludes `debug-heappoison`'s poison/quarantine
machinery to preserve fast-repro timing). Next session: get a sample under
`debug-heappoison` (which DOES include corruption-probe) that hits this
specific `add_free_region` walk-loop failure, and read its
refcount/mapcount/MANAGED output.

### Fast-repro recipe
```
mcp__qemu__qemu_start(arch=x86_64, features="debug-boot,debug-dealloc-diag", smp=2)
mcp__qemu__qemu_continue(...)   # times out at 120s internally, boot continues regardless
# wait ~25s, then qemu_serial() and grep for PANIC/FAULT/dealloc-failed/malformed-*
```
`debug-dealloc-diag` (new this session, kalloc-only, klog dep, ZERO
alloc/dealloc behavior change) surfaces the `HoleListError` tag + addr/size
on every previously-silent failure branch in `add_free_region`/plain
`dealloc`. Use `debug-heappoison` instead (same repro, but ~500s not ~25s,
and includes corruption-probe/redzone/quarantine) when you need frame-
ownership data, not just the error tag.

**Caution**: `debug-heappoison` changes kalloc's internal timing enough to
mask/delay the fast repro — don't mix it with `debug-dealloc-diag` when
speed matters. `translate_at_va` (not `translate_4k`) is required for any
new page-walk code touching kernel-image VAs — the image is 2 MiB-block
mapped, `translate_4k` bails with a false "not mapped" on huge/block leaves
(learned the hard way this session, see B1325/PR#3767).

### Concrete next step
1. Boot `debug-heappoison` repeatedly (now that `probe_corruption` is wired
   into `add_free_region`'s walk-loop) until a sample hits that exact path
   and prints corruption-probe output — read refcount/mapcount/MANAGED for
   the corrupted node's backing frame. A MANAGED=1 hit there is the
   smoking gun (double-owned buddy frame); MANAGED=0 rules that theory out
   for this occurrence and points back toward a 4th unsynchronized Task/
   global field somewhere.
2. If corruption-probe comes back clean, grep for any OTHER `Task` field
   (or global singleton) with the same raw-`UnsafeCell`-read-by-foreign-
   caller pattern that fd_table/mm/exe_path had — `parent_arc`, `ctty`,
   `cmdline`, `environ`, `sigactions` were surfaced this session (see the
   B1326 investigation's grep of `UnsafeCell<` in `task.rs`) but NOT
   audited for foreign-task raw reads the way fd_table/mm/exe_path were —
   do that sweep first, it's cheap and mechanical.
3. Re-audit `SlotTable::resize`'s allocation burst specifically for an
   off-by-one or size-class edge case now that 3 known confounders are
   fixed — the "clean" verdict from this session's zram-path investigation
   was thorough but pre-dates the fd_table/mm/exe_path fixes; worth a fresh
   look with those ruled out.
4. Once `make smoke` passes for real (not `SKIP_SMOKE=1`), it becomes the
   cheap CI-equivalent gate for every future PR touching kernel/ — no
   excuse not to run it given the ~25s repro cost now.

### Housekeeping
- PRs merged this session: #3766 (state.md compaction + B1324 verify),
  #3767 (B1325, corruption-probe MANAGED-flag fix), #3768 (B1326, the 3
  cross-CPU UAF fixes above).
- Kill stale `qemu-system-x86_64` before new boots — bash sandbox can't
  kill processes; ask user if instances accumulate.
- `nohup cmd &` does NOT reliably survive across tool calls in this
  harness — use `run_in_background: true` on Bash, or the qemu MCP's own
  background-continuation, not manual nohup.
- First command next session: boot `debug-heappoison` (not
  `debug-dealloc-diag`) and repeat until the `add_free_region` walk-loop
  failure fires with corruption-probe output (next-step item 1 above).
