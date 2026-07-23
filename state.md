## Handoff: B1347 corruptor = PROCESS-context (DEFINITIVELY, not interrupt); writer still unnamed

### Headline (13 boots, diagnostics C206-C211 all merged)
The multi-session heap corruptor (~90% boots crash at `[ZRAM-SYSFS] disksize=`, ~21-25s) is now
DEFINITIVELY characterized but the WRITER is still not named. Robust, repeatedly-confirmed facts:
- **PROCESS context, NOT an interrupt — PROVEN.** C210 added `IRQ_SEQ` bumped at the top of every
  `oxide_irq_dispatch`, recorded per kalloc-op + at detection. On the detection boots `irqseq` is
  CONSTANT across the whole recent-op ring AND at detection ⇒ NO hard IRQ fired in the write
  window. (Critical: hard IRQs don't set preempt_count's hardirq bits — `preempt.rs:79` — so
  `ctx.in_irq` alone could NOT rule out an IRQ; the irqseq probe does.) Kills the "unprotected
  interrupt" hypothesis for this corruption. It's synchronous process-context code.
- **Writer damages offset-0 AND offset-8** (16 bytes) of a block = an `ArcInner{strong@0,weak@8}`
  refcount op on an over-released Arc/Weak, OR a 16-byte struct write.
- **Victim varies EVERY boot (coincidental recycling)**: GcNodeInner, InetSocket, Vma, VMA-tree
  BTreeMap node, `BTreeMap<u64,u64>` node, PollWaiter, a Task's XSAVE area (xrstor #GP), a
  `Vec<Weak<Dentry>>` dcache bucket (d_lookup_reval #UD), a zram Slot ptr (#PF). Provenance names
  the victim, never the writer.
- **Manifests 4 ways** (same offset-0/8 write, different block hit): kalloc free-list panic;
  xrstor #GP (scribbled XSAVE header); #UD in `d_lookup_reval` (scribbled dcache Weak vec); #PF
  (scribbled pointer). `current()` sometimes returns a garbage tid ⇒ a corrupted Task / stale
  `rq.current`.
- **set_disksize is NOT the write site** (C211 checkpoints): sprinkled `kalloc::checkpoint()` calls
  through `store()→set_disksize→initialize_compressors` ALL logged `ok` on a boot that then #UD'd
  in dcache. So the write is elsewhere in the zram-generator window — the ring on that boot showed
  `pidfd_open` / `recvmsg` SCM-control delivery / `snapshot_tasks_for_pid_lookup` (systemd process
  mgmt during the exit burst), not the zram code.

### boot7 (debug-as-lifetime + C208 ring) — EXIT-BURST trigger + comprehensive audit done
The corruption fires right after a BURST of ~6 process exits (systemd generators tids 4180-4188),
each tearing down an AddressSpace with `vmas=110` (AS-LIFE `drop-enter`) — freeing ~660 Vma/VMA-tree
nodes into the static heap — THEN the zram-generator (tid 4196) runs and the corruption is detected
in its disksize window. Victim boot7: `alloc_ip=AddressSpace::mmap_with_may`,
`free_ip=drop_in_place::<Vma>` (a freed Vma). Each AS root drops EXACTLY ONCE in the trace — NO AS
double-drop. Write is within ~32 kalloc ops of the crash (exit-burst-reap → early-zram window);
tight-validate arms at mem_limit, too late to see the write, only its aftermath.
**RULED OUT BY AUDIT (all Arc/Weak/u64 or balanced into_raw/from_raw — NOT the writer):**
`unix_sock::gc`, `active_mm.rs` grab/drop/park, `Task::replace_mm` (moves the Arc), `switch.rs`
finish_switched_from / reap_pending / increment_strong_count (all on LIVE rq.current),
`zombies::park_for_wait4` (live current), `anon_vma.rs` + `file_rmap.rs` (Weak<AddressSpace> + value
ranges, never a raw VMA ptr), `File::Drop`, `InetSocket` (no custom Drop, passive victim), the
fdtable/unix_sock/File raw-Arc sites (only `Arc::as_ptr` identity keys). The writer is a subtle
LONG-LIVED stale heap pointer that survives the exit-burst free and is written later — NOT in these.
**Value clue is WEAK**: boots 2&4 wrote `[0,95,0,308]` but boot3/boot7 wrote size=0 — value varies.
**DECISIVE NEXT TOOL (static audit exhausted):** electric-fence arena — route static-heap allocs in
the arm window through a page-granular arena, `mprotect`-RO on free, so the stray write #PFs at the
STORE instruction (names the writer RIP directly). OR audit LONG-LIVED heap-pointer holders written
in process context at a later QS: `sync::call_rcu` boxed closures capturing a raw ptr, deferred
work, timer one-shot args. The C206-C208 instrument reliably captures the victim/context; only the
writer's RIP is missing, and only a fault-on-write (electric fence) or precise HW watchpoint gets it.

### earlier lead (boot6, C208 recent-op-IP ring) — mm / AddressSpace teardown
Boot6 victim provenance: `alloc_ip` = `BTreeMap<UserVirtAddr,Vma>::insert` (a VMA-tree node),
`free_ip` = `Arc<vmm::AddressSpace>::drop_slow` (an AddressSpace being torn down),
`prev_alloc_ip` = same BTreeMap::insert (slot reused as VMA nodes). So the victim is a **VMA
BTreeMap node freed by AddressSpace teardown** — a process's memory map being freed on exit.
The offset-0 write = an Arc strong-count decrement on that freed AS/VMA memory. This is the SAME
neighborhood as the RESOLVED B712 switch-tail Task UAF (below) — a SIBLING stale-`Arc<AddressSpace>`/
raw-pointer bug in the process/AS teardown path. Prime suspects (process context, single-CPU):
`sched/live/schedule/switch.rs` finish_switched_from / reap_pending (raw Task ptr, `into_raw`
at :316) + `active_mm.rs` (per-CPU `AtomicPtr<AddressSpace>` grab/drop/park via into_raw/from_raw
— internally balanced, but audit the CALLER sequence for a double-release) + rmap/anon_vma
(`anon_vma.rs:80` uses `mm.as_ptr()` as a key — check nothing derefs a stale VMA/AS after
`as_teardown`). NEXT: boot with `debug-as-lifetime` (built-in AS-transition tracer) + dealloc-diag
to correlate an AS grab/drop/park with the corruption, OR audit switch-tail + active_mm callers.
The recent-op ring (C208) dumps the last 48 alloc/free (ip,base) on detection — use it to see
which teardown op freed the victim + what ran right after.

### Earlier lead — SOCKET / fd teardown (superseded by the mm lead above, but same window)
Victim provenance across boots: boot4 `ArcInner<GcNodeInner>` (`GcNode::new`/`gc::collect`),
boot5 `InetSocket` (`InetSocket::new_in`/`drop_in_place::<InetSocket>`). BOTH socket-subsystem
objects freed in process context. Victims vary run-to-run (also code bytes, int-pairs, no-prov)
⇒ provenance names the VICTIM, not the writer — the socket objects are coincidental recycling:
systemd's heavy AF_UNIX socket teardown floods this heap region right before the zram-generator
runs. BUT the writer is active in that same window, so socket/fd teardown is the prime suspect.
`gc.rs:152` installs `collect` (AF_UNIX GC) as a GLOBAL `vfs::set_file_ref_drop_hook` → runs on
EVERY fdtable fd-drop (`fdtable/ops.rs:135,197,230,326`) in process context. AUDITED `gc.rs`
clean (Arc/Weak/u64 only); the raw-Arc grep of fdtable/unix_sock/File paths found only
`Arc::as_ptr()` used as identity KEYS (never deref'd). So the stale write is a plain over-released
`Arc<T>` drop OR a struct-field write via a stale pointer — NOT an obvious `from_raw`/`into_raw`.
NOTE `sock/packet.rs:83` `packet_origin(sock)=sock as *const InetSocket as usize` — check its
consumers for a stale deref (AF_PACKET ring/tx), low-priority.

### RULED OUT this session (audited clean — Weak/strong-Arc/balanced, NOT the writer)
`unix_sock::gc` (collect/GcNode), `active_mm` grab/drop/park, `Task::replace_mm`, `switch.rs`
finish_switched_from/reap/increment_strong_count (LIVE current only), `zombies::park_for_wait4`,
`anon_vma`+`file_rmap` (Weak<AS>+ranges), `File::Drop`, `InetSocket` (no Drop), `PollSubscribers`
+`PollWaiter` (Weak, notify upgrades), `cpustat::charge_current_tick`+`timers::account_cpu_tick`
(strong-Arc owner), `registry::snapshot_tasks_for_pid_lookup` (Weak), `socket::install_received_fds`
(owned Arcs, balanced), the fdtable/unix_sock/File raw-Arc sites (Arc::as_ptr identity keys only).

### First task next session — CATCH THE WRITER (static audit EXHAUSTED; need fault-on-write)
23 subsystems audited clean; the writer is a subtle over-released Arc/16-byte stray write NOT in
any obvious path. Instrumentation reliably captures victim+context+IRQ-status but the write is a
stray store between kalloc ops (not a kalloc op) so no ring/validate names its RIP. The ONLY tool
that names the store instruction is FAULT-ON-WRITE:
- **Electric-fence arena (the decisive build):** during the arm window route static-heap frees
  through a page-granular arena, `mprotect`-RO on free (no reuse), so the stray write #PFs at the
  store — fault.rs already dumps rip+GPRs+recent-op ring. Cost: memory (fence pages) — bound it by
  fencing only a size band or only during the ~1s window. This is a real allocator change (~a
  focused session), NOT another blind boot.
- Cheaper first try: a HW data watchpoint set from GDB on the exact bad_node addr captured at a
  detection, re-armed on the next same-build boot (layout is fairly stable under kvm for the same
  build+images — worth one attempt before the arena).

### (superseded next-steps — kept for context)
The C206/C207 instrument now RELIABLY catches the corruption at the op boundary and names the
DETECTING context (always tid=zram-generator, syscall=write, in_irq=0, last_op_ip=
CompressionConfig::initialize's Arc::new) + the victim provenance — but NOT the writer's RIP
(the write is a stray store between kalloc ops, not a kalloc op).
- **HW-watchpoint CAVEAT**: x86 has only 4 debug regs × 8 bytes = 32 bytes total, and the victim
  address VARIES run-to-run even same-build (`81c5e2f0` / `81c5f110` / `8197de38`) — so "watch the
  region" is NOT feasible. Only workable HW-watch: rotate DR0-3 over the LAST 4 freed blocks during
  the tight window and hope the write hits one of the last-4-freed (the victim may be freed many
  ops earlier, so coverage is partial). Low-confidence.
- **PATH A (recommended, boot-free first): audit socket/fd-close teardown** for a plain
  over-released `Arc<T>` drop / stale struct-field store, guided by the strong signal (process
  context, tid=zram-generator's fd closes, victims cluster on socket objects — InetSocket, GcNode).
  Suspects: `File::Drop` (`vfs/file/lifetime.rs`: release_file, flock, dput/iput), AF_UNIX
  close→`unix_sock::gc::collect` (file-drop-hook), listener accept-queue drop, `sock/packet.rs:83`
  `packet_origin` consumers. Look for a struct that keeps a `*const`/over-shared `Arc` to a socket
  it doesn't own past free.
- **PATH B (instrument): recent-op-IP ring** — record the last N kalloc caller IPs; on op-start
  detection dump them, bracketing the exact call sequence [last-clean-op → stray write → detecting
  op]. One boot; narrows the writer's code region to what runs just before initialize's Arc::new.

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

### Session scoreboard (this session: 3 fixes + C206/C207 diagnostics, all merged)
B1344 IRQ-safety deadlock; B1345 msleep one-shot stale-WaitList UAF; B1346 tasklet_kill
one-shot cancel; C206 diag-validate context capture + tight-validate + validate() owns_range
fix (PR#3845 merged); C207 tight-mode op-START precheck (names detecting context + victim
provenance reliably). Both arches build. Prior: C202/C203/C204/C205, D360/D362.

### Boot recipe (unchanged)
`qemu_start(x86_64, features="debug-boot,debug-dealloc-diag", paused=false)` → **then
`qemu_continue`** (REQUIRED; times out 120s = expected) → `qemu_serial` (>90KB → saved to file;
`jq -r .result` then grep `tight-validate-armed|diag-validate-failed|corrupt-node prov|merge-header-outside|[PANIC]`).
`addr2line -Cfi -e <build>/…/oxide-x86_64 0x<ip>` names alloc/free sites. `qemu_stop` each; `qemu_list` first.
