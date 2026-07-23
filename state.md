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

### STRONGEST lead (boot6, C208 recent-op-IP ring) — mm / AddressSpace teardown
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

### First task next session — CATCH THE WRITER (instrument done; two feasible paths)
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
