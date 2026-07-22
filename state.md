## Handoff: kalloc free-list corruption hunt (handoff.md original bug)

### Headline
Still unresolved. Session goal (`/goal`): "resolve all issues in handoff.md
linux style no hacks no split truth." Bug: a live `HoleHdr` free-list node
periodically gets trashed (`kalloc back/front fragment invalid` panic),
sometimes showing pure quarantine/redzone poison (`0xEE`/`0xA5`), sometimes
real-looking garbage. A second, confirmed-independent victim class also
fires: a running Task's kernel-stack guard-canary (`stack[0..32]`) wiped
from byte 0 (`offset=0`), 3/3 reproducible, always in the ~475-530s late-boot
window (systemd/GNOME userspace churn). Both match the original handoff.md
report and are believed to be the SAME underlying corruptor.

### Latest boot (this session, B1324 verify) — CONFIRMS fix, same bug class
`kalloc front fragment invalid` at ffffffff822a5b78, header = pure
`0xEEEEEEEEEEEEEEEE` (quarantine poison). `corruption-probe` now correctly
reports `unresolved (not an HHDM address -- static-heap/kernel-image VA, no
PFN map)` — confirms B1324's VA-classification fix works (previously
misreported this class of address as HHDM "out-of-range"). No new lead on
the writer itself; static-heap corruption-probe (VA->PFN reverse map for
the kernel image's own linked range) still doesn't exist — needed to get
refcount/mapcount data on THIS class of address, same as B1322 already gets
for HHDM addresses.

### Current leading theory
A genuine use-after-free OUTSIDE kalloc (not a kalloc bookkeeping bug).
Basis: two independent hosted fuzz harnesses (single-threaded + SMP) driving
kalloc's own alloc/dealloc/quarantine/grow logic directly both came up
clean; manual trace of every kalloc-internal list-linkage path found no
defect; corrupted bytes are sometimes real data, sometimes exactly a poison
pattern that WAS legitimately there earlier — consistent with some caller
elsewhere holding a raw pointer past its allocation's real lifetime and
writing through it onto whatever now occupies that address (a live object,
a quarantined block, or a free hole header). Retracted theory: simple
neighbor-merge-absorption-of-a-freshly-reinserted-block — ruled out because
`add_free_region` always writes a fresh valid header before `try_merge`
runs, so an absorbed node's bytes would show a real recently-written header,
not untouched poison (see 706154f86).

### Ruled out (high confidence, don't re-test)
- Single-subsystem buggy frees (zram, ext4, dentry Drop paths)
- Linear/adjacent-neighbor buffer overflow (redzones intact)
- kalloc's own free-list/carve/split/merge bookkeeping (2 clean hosted fuzz
  harnesses, single-threaded + SMP; manual trace of holes.rs)
- `debug-smp`/`debug-stack-guard`/growth-timing as causal triggers (were
  coincidence or a separate now-fixed PMM PFN-0 bug, B1315)
- Wide static raw-pointer audit: vsock, console/vtconsole/fbcon, serialtty,
  clone/exit syscalls, futex wait/waitv/core/robust, sched ttwu/wait_list/
  tick_deadline — no write-corruption defect found (2 unrelated minor bugs
  found instead: fbcon font leak, Task::exe_path torn-read race — neither
  matches this bug's shape, noted for separate small PRs, not yet filed)

### Concrete next step
1. Build a static-heap VA->PFN reverse map (kernel image's own linked range
   + load-bias) so corruption-probe (B1322) can resolve refcount/mapcount
   for kernel-image-VA hits too, not just HHDM ones — this is the single
   highest-leverage remaining diagnostic gap. Needed for BOTH the kalloc
   free-list victim (this session's hit lives at a static-heap VA) and the
   Task stack-guard victim (also static-image VAs).
2. Get more stack-guard-canary samples (3/3 so far, cheap ~500s each,
   well-characterized: current_ref(), offset=0, crossed_16k=0 intact,
   tid cluster 4298/4299/4309) — narrow the ~475-530s window with finer
   checkpoints to bisect which service/syscall is active at the exact wipe.
3. Extend hosted fuzz harness with a grow-hook-backed heap (PMM growth
   interaction with active free list + quarantine) — not yet covered by
   either existing harness.
4. Live GDB backtrace at the corrupting write site would resolve this
   outright but the bridge has wedged on both pre-boot and post-panic
   interrupt attempts before (see `qemu-gdb-bridge-unresponsive-on-interrupt`
   memory) — treat as unreliable, prefer serial/klog forensics.

### Session fixes merged (chronological, this + prior session)
B1309 (#3735) HoleList::validate/dump, merge-trail, periodic_validate.
B1310 (#3736) poison.rs self-deadlock fix, EvictHistory.
B1311 (#3740) x86_64 free_ip capture, Dentry drop d_op hardening.
B1312 (#3742) dcache-wide periodic d_op sanity sweep.
B1313 (#3744) wired dead redzone code, ruled out linear overflow.
B1314 decoupled stack-guard canary check from debug-smp.
B1315 (#...) named+fixed PMM PFN-0 double-meaning bug (was root cause of
  the ext4-root-mount Eio blocker, not feature-specific flakiness).
B1316 tightened VALIDATE_INTERVAL 64->8.
B1317 hosted fuzz harness (free-list-never-overlaps-quarantine), clean.
B1318 seq= diagnostic numbering on KALLOC log lines.
B1319 SMP hosted fuzz harness variant, clean.
B1320 (#3763-adjacent) fixed if-let lock-lifetime-extension self-deadlock
  in periodic_validate.
B1321 fixed x86_64 panic handler using an allocating klog sink while
  holding kalloc's own lock (self-deadlock, swallowed panic output).
B1322 corruption-probe hook: resolves HHDM addr -> PFN -> refcount/mapcount.
B1323 per-syscall-entry stack-guard checkpoint.
B1324 (#3764) fixed corruption-probe misclassifying kernel-image VAs as
  HHDM (boot-verified this session, see above).

### Housekeeping
- Kill stale `qemu-system-x86_64` before new boots (bash sandbox can't kill
  processes — ask user if stale instances accumulate).
- qemu MCP was dead at start of prior session, confirmed back up this
  session (qemu_list/qemu_start/qemu_continue all working normally).
- First command next session: boot
  `debug-boot,debug-heappoison,sched/debug-stack-guard` again for another
  stack-guard-canary or free-list sample, OR start on the static-heap
  VA->PFN reverse map (next-step item 1) if going for the diagnostic
  upgrade instead of more raw samples.
