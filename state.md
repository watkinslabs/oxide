## Handoff: corruptor is PROCESS-context (NOT interrupt), in the zram-generator disksize-write window

### Headline — B1347 narrowed to process context + a live-instrument (C206) that names the running context
The multi-session heap corruptor (crashes ~90% boots at `[ZRAM-SYSFS] disksize=`, ~21-24s)
was chased this session with a NEW diagnostic (C206, branch `C206-kalloc-diag-validate-ctx`,
committed, PR pending aarch64 build). Four boots produced hard new evidence:

- **PROCESS context, NOT an interrupt.** Tight-mode context capture at first detection:
  `ctx.tid=4195 ctx.syscall=1(write) ctx.preempt=0 ctx.in_irq=0`. tid 4195 = the
  **zram-generator** (`/usr/lib/systemd/system-generators/zram-generator`). This REVISES the
  long-standing "unprotected interrupt write" theory for THIS corruption — the write is in
  process context, in tid 4195's `write()`-to-sysfs syscall window (mem_limit then disksize).
- **Writer damages offset-0** of a recently-freed static-heap block (`ArcInner` strong-count /
  `HoleHdr.size` → `0` or garbage). Confirms the prior "stale raw-Arc refcount op" reframe.
- **Victim varies run-to-run** (boot1 code-like bytes; boot2 int-pairs `[0,95,0,308]`; boot3
  no ring record; boot4 = `ArcInner<GcNodeInner>`). Provenance names the VICTIM, not the writer.
- **Recent write**: boots 1&2 (validate every 32 ops all boot) got 0 catches ⇒ corruption
  appears WITHIN ~32 kalloc ops of the crash, i.e. inside the disksize-write window.

### Strongest new lead — the AF_UNIX SCM_RIGHTS garbage collector (`net::unix_sock::gc`)
Boot4 victim provenance: `alloc_ip=GcNode::new`, `free_ip=gc::collect`. `gc.rs:152-154`
installs `collect` as a GLOBAL `vfs::set_file_ref_drop_hook` → `collect()` runs on EVERY
fdtable fd-drop (close/teardown, `fdtable/ops.rs:135,197,230,326`) in **process context** —
including tid 4195's sysfs-file closes. Matches the process-context signal exactly.
CAVEAT: I audited `gc.rs` — all refs are Arc/Weak/u64-IDs, no obvious stale-raw write; the
`GcNodeInner` victim may be coincidental recycling. But the file-drop-hook + process-context
fit makes the GC / File::Drop-hook path the #1 region to instrument next.

### First task next session — CATCH THE WRITER (two decisive, cheap moves)
1. **Close the instrument gap** (C206 residual): in tight mode the crashing carve panics
   INSIDE `holes.alloc/dealloc` BEFORE the end-of-op `periodic_validate_diag` runs (boot4 got
   0 diag hits for this reason). Add a validate at the START of alloc/dealloc when
   `TIGHT_VALIDATE` is set (before the carve), so the carve-panic can't preempt detection.
2. **HW write-watchpoint on the victim slot**: the recurring bad node sits in `ffffffff81c5exxx`
   / `81633xxx` (static BSS heap). Arm `debug-hw-watchpoint` DR0-3 over that region when
   `arm_tight_validate` fires (disksize store), HOLD them; the stale offset-0 store #DB-names
   the writer rip via hal-x86_64 `[HWWP]`. (C203 fixed its false-positive storm; the v1
   single-block scope missed because it watched only the last freed block.)
3. **Audit the file-drop-hook chain in process context**: `collect()` (AF_UNIX GC) + File::Drop
   (`file/lifetime.rs`: release_file, flock hook, dput/iput) for a stale `Arc`/`Weak` refcount
   op or raw-pointer write to a freed `ArcInner`. Also re-examine the sched/mm raw-Arc ops
   (wait_list/runqueue/switch.rs) — B1345 was exactly this shape, in process context too.

### C206 instrument (committed on branch; feature-gated `debug-dealloc-diag`, no-op otherwise)
- `kalloc::current_ctx` hook (early.rs `kalloc_current_ctx`) packs tid/last_syscall/preempt/in_irq.
- `periodic_validate_diag`: full-free-list walk on alloc AND dealloc; every 32 ops, or EVERY op
  in tight mode. Logs bad node + decoded ctx + free-IP provenance + PMM classification.
- `arm_tight_validate()` (always-compiled no-op off-feature) armed by the zram `mem_limit`/
  `disksize` sysfs store (`sysfs/src/block/zram.rs`; sysfs now deps kalloc).
- **Real fix inside `holes.rs::validate()`**: now also checks `size % MIN_HOLE_ALIGN` and
  `owns_range(addr, addr+size)` — matches the carve's own gate (holes.rs:762). Without it a
  node whose corrupted size extends just past its region-end (no u64 overflow) passed
  validate() yet tripped the carve's listed-free-outside — a real diagnostic blind spot.

### Separate REAL bug still unfixed (agent #1, prior session) — OFD/POSIX locks leak on close
`fs/posix_lock.rs:242` `release_for_file` documented "called from `vfs::set_drop_hook` chain"
but `vfs::set_drop_hook` is NEVER called; File::Drop's flock hook is gated on `flock_op != 0`
which is never written (dead gate). `fcntl(F_OFD_SETLK)` locks survive close and leak in
`posix_lock::TABLE`. FIX: fire release unconditionally in File::Drop (drop the dead gate) or
fold into `inode.file_lock_context().release_file(self_ptr)`. Correctness bug, NOT the corruptor.

### Session scoreboard (this session: 3 fixes + C206 diagnostic, all pushed)
B1344 IRQ-safety deadlock; B1345 msleep one-shot stale-WaitList UAF; B1346 tasklet_kill
one-shot cancel; C206 diag-validate context capture + tight-validate + validate() owns_range
fix (branch pushed, PR pending aarch64 build green). Prior: C202/C203/C204/C205 diagnostics,
D360/D362 characterization.

### Boot recipe (unchanged)
`qemu_start(x86_64, features="debug-boot,debug-dealloc-diag", paused=false)` → **then
`qemu_continue`** (REQUIRED; times out 120s = expected) → `qemu_serial` (>90KB → saved to file;
`jq -r .result` then grep `tight-validate-armed|diag-validate-failed|corrupt-node prov|merge-header-outside|[PANIC]`).
`addr2line -Cfi -e <build>/…/oxide-x86_64 0x<ip>` names alloc/free sites. `qemu_stop` each; `qemu_list` first.
