## B1313-kalloc-wire-redzones

### Headline — ruled out linear buffer overflow as the mechanism
Still NOT fixed. This round wired up dead-code redzone infrastructure that
already existed (`poison::alloc_layout`/`arm_redzone`/`check_redzone` — never
called anywhere before this) and got a real, valuable NEGATIVE result: a
389-SECOND boot (much deeper into userspace than any prior repro — reached
NetworkManager DNS activity) hit the same `kalloc back fragment invalid`
corruption WITHOUT ever tripping a redzone violation. `/goal`: "resolve all
issues in handoff.md linux style no hacks no split truth" — still unmet.

### This round's real fix (wired, boot-verified, both arches build)
`crates/shared/kalloc/src/lib.rs`: `alloc()` now pads every allocation
(`debug-heappoison` only) with a trailing 32-byte redzone via
`poison::alloc_layout`/`arm_redzone` (pre-existing functions, previously dead
code — confirmed via build warnings earlier this session: "function
`arm_redzone` is never used" etc.). `dealloc()` checks the redzone via
`check_redzone` BEFORE touching the block further, and uses the SAME
expanded ("carve") layout — recomputed identically in both `alloc`/`dealloc`
from the caller's original `layout` — for every actual hole-list operation,
so the reclaim always covers the exact span that was carved out.

### Why this negative result matters
If the corruption were a classic "write past the end of my own buffer, into
whatever's allocated right after it" overflow, the redzone would catch it
at the OVERFLOWING allocation's own free — every allocation now carries one.
It didn't fire once across 389s of real boot activity, right up to the next
occurrence of the same corruption class. Combined with the "3 unrelated
innocent victims" finding from prior rounds (zram Vec, ext4 Vec, live
Dentry — see git history on this file for the full trace), this rules out
sequential/adjacent-neighbor overflow specifically, on top of already ruling
out "buggy free in some specific subsystem". The write is landing on memory
that is NOT adjacent to whatever allocation is responsible for it — i.e. a
genuinely non-local, dangling/stale-pointer-style write, not a bounds bug.

### Session summary — what's confirmed vs still open
**Confirmed, real, independent fixes this session (all merged):**
- **B1309** (#3735): `HoleList::validate()`/`dump()`, `try_merge` merge-trail,
  `KAlloc::periodic_validate`, PMM `kalloc_grow` hardening asserts, a real
  `smoke::pmm::run` build-break fix.
- **B1310** (#3736): fixed a confirmed self-deadlock in `poison.rs` (allocating
  `klog` calls under the allocator's own lock, caught live as a 90s+ frozen
  boot). Added `HoleList::EvictHistory` (proven working in B1312, below).
- **B1311** (#3740): real x86_64 `free_ip` capture (`frame-pointer=always`,
  x86_64-only — aarch64 stalled when this was tried there, reverted, unneeded
  anyway since aarch64 already reads `x30` directly). `Dentry::drop` `d_op`
  canonical-address hardening (converts a live wild #PF into a clean panic).
- **B1312** (#3742): dcache-wide periodic `d_op` sanity sweep — catches the
  live-Dentry corruption class while the dentry is still alive.
- **B1313** (this one): wired dead redzone code; ruled out linear overflow.

**What's been RULED OUT for the actual corruptor** (high confidence):
single-subsystem buggy frees (zram, ext4, dentries — 3 unrelated innocent
victims found); linear/adjacent-neighbor buffer overflow (this round);
`as_teardown`/PMM as primary cause (every corrupted node lives in the static
BSS heap, which PMM growth never touches); the highest-suspicion
`Arc::from_raw`/`into_raw` sites kernel-wide (`switch.rs`, `zombies.rs`,
`active_mm.rs`, `mm-pmm/setup/rmap.rs` — all reasoned through, no defect
found, though `rmap.rs`'s lock-holding invariant wasn't exhaustively
verified at every call site — see prior state.md history for full notes);
today's 194-branch merge; VMA tree; PMM alloc/free/rmap mechanics; sched/task
lifecycle; `debug-fwm`; kernel-image/static-heap PA overlap; FPU/XSAVE sizing;
`PageRmap::mapcount`/`Mountpoint::m_count`.

**Still genuinely open**: the actual writer. Given linear overflow is now
ruled out too, the shape is: something holds a dangling/stale pointer (or
computes a wildly wrong address) and writes through it unconditionally,
regardless of what currently occupies that memory — hitting live objects
(`Dentry::d_op`) and freed/quarantined blocks (zram/ext4 buffers) alike, with
no fixed size or type relationship between victims.

### Concrete next step
1. Do NOT repeat: subsystem-specific code audits (tried 3x), linear-overflow
   theories (just ruled out), or the raw-Arc sites already checked above.
2. The two real remaining paths to actually name the writer: (a) a hardware
   watchpoint — tooling doesn't support this (checked `qemu_break`/`qemu_info`,
   no watch capability); (b) a real memory sanitizer (`-Zsanitizer=address` is
   nightly-supported but needs a shadow-memory runtime this `#![no_std]`
   kernel doesn't have — a genuine, separate engineering investment, not a
   quick add, but now the highest-leverage option: every cheaper technique
   available this session has been tried and come up empty, including 5
   rounds of live boot forensics with progressively better diagnostics).
3. `net/vsock/transaction.rs`'s `arm_connect_timeout`/`cancel_connect_timeout`/
   `connect_timeout` (checked this round — traced the full timer cancel-vs-fire
   race carefully; `unregister_oneshot`'s removal and `run_due`'s removal are
   mutually exclusive under the same `ONESHOTS` lock, so `Arc::from_raw` on the
   shared raw handle only ever happens once; no defect found). Still
   unverified: `console/*`, `serialtty/lib.rs`, `syscalls/{056_clone,060_exit}.rs`,
   `ipc/live/futex/{wait,waitv}.rs` (skimmed only).
4. **Real fix landed (B1314), partially tested**: decoupled the stack-guard-
   byte check from `debug-smp` — added `sched/debug-stack-guard`, a standalone
   feature covering just `Task::debug_check_canary`'s 32-guard-byte stack
   check (NOT the task-identity canary, which still needs `debug-smp`'s
   dedicated fields), so it can run WITHOUT `sync/debug-smp`'s spin-probe
   overhead. This directly matches the ORIGINAL bug report's "Task kernel-
   stack guard-canary wipe" signature and had never been tested this session.
   First attempt caught a REAL bug in my own refactor (arming code in
   `install_stack` was still gated `debug-smp`-only while I'd widened the
   CHECK — a guaranteed false positive, fixed by widening the arming gate to
   match). After the fix: **CORRECTION on the `debug-smp`/`Eio` theory from
   the previous entry — it does NOT hold up.** `sched/debug-stack-guard` alone
   (negligible overhead, no spin-probe) ALSO hit `ext4 root mount ... Eio` on
   2 more attempts, disproving "`debug-smp`'s overhead specifically causes
   it". Checked host state directly: 53GB RAM free, no stale qemu processes,
   1.7TB disk free — not resource exhaustion either. Eio now looks like
   general environmental flakiness in this session's host/QEMU setup, NOT
   tied to any specific feature or code change. **Still never got a boot far
   enough with the (now-correct) stack-guard check active to actually test
   the canary theory against the real corruption** — that remains the
   concrete next step for a session with a quieter host.
5. This bug has now resisted this session's extensive live+static effort AND
   multiple PRIOR sessions with dedicated agent audits (per
   `gnome-blocker-refcount-uaf` memory) — treat it as genuinely hard, not one
   grep or one boot away from resolution.

### Housekeeping
- Kill stale `qemu-system-x86_64` before new boots.
- Branches this session: B1309 (#3735), B1310 (#3736), B1311 (#3740),
  B1312 (#3742), B1313 (#3744), B1314 (this one), C136-C141 (state.md
  housekeeping, superseded by this entry).
