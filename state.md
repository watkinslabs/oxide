## Handoff: kalloc/Arc corruption hunt — fast repro found, 6 real UAFs fixed, root cause still open

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

### Post-B1326 findings (same session, continued)
- **`debug-heappoison` is too slow for iteration — user explicitly vetoed
  it** ("not waiting 15 or 20 minutes to test"). Use `debug-dealloc-diag`
  only for all future iteration; accept not having corruption-probe/
  redzone/quarantine data unless truly necessary, and if you do need
  `debug-heappoison`, say so and expect ~1 boot, not a loop.
- **The corruption is NOT fully deterministic even across identical
  builds.** Two `smp=1` boots of the exact same freshly-built binary hit
  DIFFERENT crash signatures (`kalloc front fragment invalid` with zero
  diagnostic output vs. a `#PF` inside `str::contains` internals with a
  truncated-pointer register pattern). This rules out "seed a hardware
  watchpoint from a previous crash's address, reboot the same build" as a
  technique — addresses and even failure shape vary run to run. Something
  in the boot is timing/ordering-sensitive independent of build content
  (scheduler jitter, I/O completion order, or similar), not purely
  content-deterministic.
- **Confirmed via `smp=1`: at least one crash sample is a genuine
  single-threaded logic bug, not a race.** A `#PF` reading through
  `r8=0xffffffff00000000` (a real kernel pointer with its low 32 bits
  zeroed) happened with only one CPU running — cross-CPU synchronization
  cannot explain this occurrence. Don't assume every remaining sample is
  SMP-related; at least one class isn't.
- **A background agent's negative-result investigation actively refutes
  the "double-owned buddy frame" theory** (not just "didn't find it" —
  the specific guards that would catch it, `frame_alloc.rs:89` and
  `boot.rs:50/53`, are unconditional and have not fired). Don't re-chase
  that theory without new evidence.
- **Found, diagnosed, AND fixed a real, independent UAF read**:
  `Ext4FrameStore::writeback_idxs` (now `framecache/writeback.rs`) planned
  a page's physical address under one lock, dropped it, then touched that
  `pa` later with no pin held — the PMM shrinker could legitimately
  evict+free the page in that exact gap. B1327 (PR #3770) added
  `debug-framecache-verify` detection; B1328 (PR #3772) closed the actual
  race by taking the SAME per-page lock the shrinker itself takes
  (`pmm::setup::try_lock_page`/`unlock_page`, mirroring zsmalloc's
  existing correct pattern) around the touch. Neither boot test triggered
  the corruption, so this fix is unconfirmed as THE root cause — but it's
  real and closed regardless.
- **Swept every other `Task` field for the same fd_table/mm/exe_path
  UnsafeCell-foreign-access pattern and found three more real instances**,
  all fixed same session:
  - `parent_arc` (B1329, PR #3773) — worse than the others: has a genuine
    **foreign writer** (`reparent_children` rewrites a live child's
    parent_arc from the exiting parent's own CPU while the child may be
    running on another CPU right now), not just foreign readers.
  - `cmdline`/`environ` (B1330, PR #3774) — same torn-`String`-read shape
    as `exe_path`, read via `/proc/<pid>/cmdline`/`environ` for an
    arbitrary foreign pid.
  - `rlimits` (B1331, PR #3776) — same shape, but with TWO confirmed
    foreign-task syscalls: `prlimit64(2)` (own prior comment already
    admitted "task may not be current") and `sched_setattr(2)`'s
    RTPRIO/NICE checks (Linux's `task_rlimit(p, ...)` contract: the
    TARGET's limits govern). ~20 call sites updated.
  - `ctty` was checked and confirmed self-only (no foreign access found,
    no fix needed) — don't re-audit it without new evidence.
  - **`fpu_state` — found, NOT fixed, different shape than the others.**
    `ptrace_fpu::get_fpregs`/`set_fpregs` (`syscalls/src/ptrace_fpu.rs`,
    dispatched from `101_ptrace.rs:360-361`) touch an arbitrary target
    task's `fpu_state` with a `// SAFETY: target parked under ptrace`
    comment that is NEVER VERIFIED — no check that the target is actually
    ptrace-stopped, no check that `cur` is even the target's real tracer
    (`traced_by`). This isn't just a missing lock (a Spinlock would stop
    torn reads/writes, matching the other 7 fixes) — it's a missing
    ptrace-stop AUTHORIZATION check, a bigger/different-shaped fix than
    this session's mechanical sweep. `fpu_state` holds no pointers
    (raw FXSAVE/NEON byte buffer per `ArchFpuBuf`), so a race here
    produces garbled FPU register state, not a UAF/memory-corruption —
    lower priority for the kalloc hunt specifically, but a real
    correctness/security gap (a tracer can read/corrupt an unrelated,
    not-actually-stopped task's FPU state). Left unfixed this session;
    needs its own PR checking `target.state()`/`traced_by` before
    dispatch, not just a field-level lock.
  - NOT audited at all this pass: `sigactions`, `seccomp_filters`,
    `posix_timers`, `arch_ctx` — lower priority, none obviously hold
    pointers read foreign-task-style the way fd_table/mm/exe_path/
    parent_arc/cmdline/environ did.
  - **None of these 7 fixes (fd_table/mm/exe_path/parent_arc/cmdline/
    environ/rlimits) has been confirmed as THE main corruption hunt's root
    cause** — every boot test after each fix still crashed via kalloc.
    They're real, valuable, independently-justified fixes regardless
    (found via careful reading + multi-agent adversarial review, not
    speculation), but the user should know the headline bug is still open
    despite 9 merged PRs this session.

### Concrete next step
1. Given 9 real bugs fixed this session (B1325-B1331, all merged) and the
   corruption still reproducing after every one of them, the remaining
   cause is very likely NOT in the Task-field-race family anymore — that
   class has now been swept thoroughly (fd_table/mm/exe_path/parent_arc/
   cmdline/environ fixed; ctty confirmed clean; sigactions/rlimits/
   seccomp_filters/posix_timers/arch_ctx/fpu_state not yet audited but
   lower priority than a fresh angle).
2. Re-run the `smp=1` truncated-pointer sample's disassembly investigation
   to completion — it was abandoned mid-session in favor of a hardware-
   watchpoint idea that turned out not to work (corruption isn't
   deterministic enough across boots of the same build to seed a
   watchpoint from a prior crash's address). A `#PF` reading through
   `r8=0xffffffff00000000` (real kernel pointer, low 32 bits zeroed) is a
   confirmed single-threaded bug — chase it directly next: get a fresh
   `smp=1` sample, resolve the fault `rip` via `nm -C <elf> | sort` +
   nearest-below lookup, disassemble with `objdump -d --start-address=...
   --stop-address=...`, and read backward from the faulting instruction to
   find what wrote the truncated pointer, the same technique that found
   the fd_table Arc-refcount-abort trap earlier this session.
3. Given confirmed non-SMP samples exist, don't over-invest further in
   synchronization theories — the next bug is more likely a plain
   single-threaded memory-safety bug (buffer overflow, wrong-size read/
   write, use of an already-dropped local) than another cross-CPU race.
4. Once `make smoke` passes for real (not `SKIP_SMOKE=1`), it becomes the
   cheap CI-equivalent gate for every future PR touching kernel/.

### Housekeeping
- PRs merged this session: #3766 (state.md compaction + B1324 verify),
  #3767 (B1325, corruption-probe MANAGED-flag fix), #3768 (B1326, 3
  cross-CPU UAF fixes: fd_table/mm/exe_path), #3769 (state.md writeup),
  #3770 (B1327, ext4 stale-frame UAF-read detection), #3771 (state.md
  writeup), #3772 (B1328, ext4 UAF real fix via try_lock_page pin), #3773
  (B1329, parent_arc cross-CPU race fix), #3774 (B1330, cmdline/environ
  cross-CPU race fix), #3775 (state.md writeup), #3776 (B1331, rlimits
  cross-CPU race fix). 9 real, reviewed, merged bug fixes total — none
  yet confirmed as THE corruption-hunt root cause. `fpu_state`'s ptrace
  authorization gap (see above) found but NOT fixed — needs a different
  shape of fix than the other 7.
- **User explicitly vetoed `debug-heappoison`-based iteration (~15-20 min
  loops) — use the ~25-30s `debug-dealloc-diag` fast repro for everything
  going forward.** Do not default back to the slow loop.
- Always `mcp__qemu__qemu_list` and stop stale instances before starting a
  new one — multiple were left running simultaneously this session
  (wasted resources, user flagged it directly).
- Kill stale `qemu-system-x86_64` before new boots — bash sandbox can't
  kill processes; ask user if instances accumulate outside MCP tracking.
- `nohup cmd &` does NOT reliably survive across tool calls in this
  harness — use `run_in_background: true` on Bash, or the qemu MCP's own
  background-continuation, not manual nohup.
- First command next session: implement the real pin fix for B1327's
  ext4 writeback finding (next-step item 1 above) — concrete, scoped,
  doesn't need a boot loop to start.
