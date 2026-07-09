# Handoff — console+desktop = one sysinit stall (multi-bug); 4 fixes merged

## Merged this session (main a0962d5e)
- **F696** ext4 read-verify completion (extent-block/dirent-tail/bitmap csum).
- **B677** AF_UNIX nonblocking read → EAGAIN (was blocking; console2.md suspect #1).
  Correct Linux-compat + hosted tests, but NOT the boot blocker.
- **B678** zombie-reap epoll-gen race: `enqueue_zombie` now bumps GLOBAL_EPOLL_GEN
  AFTER the zombie is in ZOMBIES (signal_child_exit's exit-time bump fires before
  the zombie is reapable → EPOLLET-suppressed reap ~45s). Code-proven; low-risk;
  NOT yet boot-verified sufficient (earlier stall blocks first).
- **D167** state handoff.

## THE reframing (correct now)
Console-login and live-gnome are the SAME problem: the graphical window is a
working fbcon/klog mirror, but **no `getty@tty1` ever runs because sysinit never
completes**. The console/VT/fbcon stack + /dev/console routing are already Linux-
correct (see console2.md "Code analysis update"). The serial `sh` prompt is the
`systemd.debug_shell=ttyS0` **debug hack** (remove for a real install), NOT a getty.
So the ONLY thing to fix is the sysinit stall.

## The sysinit stall = MULTIPLE distinct bugs (live-boot confirmed via qemu MCP)
Clean boot (features=debug-watchdog, no debug-boot flood): systemd reaches the
socket/target setup in ~2.5s, then CRAWLS ~45s+ per userland-touching service.
Kernel + serial debug-shell stay fully alive throughout (not hung). Confirmed:

1. **FRONT BLOCKER — `systemd-hwdb update` BUSY-SPINS in pure userspace.** At the
   ~10s stall, exactly one non-shell task is state `R`: `/proc/39 [systemd-hwdb
   update]`. `/proc/39/stat` utime≈5712 stime=0 → ~57s of USERSPACE CPU, ZERO
   kernel time, under KVM (native speed). It reads the 35 input files
   (/usr/lib/udev/hwdb.d/*.hwdb, 9.3MB, all read fine) then loops FOREVER building
   the trie — **never reaches the write phase** (no hwdb.bin temp file appears; the
   old 13.5MB /etc/udev/hwdb.bin stays read-only+untouched). In a debug-boot run it
   spun to the 90s DefaultTimeoutStartSec and systemd killed it ("Failed to start
   systemd-hwdb-update"), then the boot limped on. On real Linux this is <2s.
   → **A userspace infinite/pathological loop triggered by our env** (a libc/hwdb
   interaction over some syscall result). NOT ext4-read (inputs read correctly),
   NOT slow I/O (stime=0), NOT TCG (KVM confirmed by fast boot).
   **Perf hypotheses DISPROVEN (rigorously, via debug-shell micro-bench):**
   - register arithmetic: 50k shell iters in ~1s → NORMAL.
   - memory/CPU: 1st sha256 of 13.5MB hwdb.bin = 5s but 2nd (cached) = ~1s → the 5s
     was ext4 COLD-READ I/O, hashing itself is ~1s = NORMAL. So userspace mem/CPU is
     NOT uncached/slow; hwdb's stime=0 spin is a genuine INSTRUCTION-COUNT blowup =
     a real loop, not slowness. Manual `systemd-hwdb update` ran >200s, never
     returned → effectively infinite.
   **ROOT-CAUSE LOCALIZED (2026-07-09d): hwdb is in a `write()`-returns-0 retry
   loop.** The spin RIP `0x7ffff71af75e` = libc offset `0x6e75e` (mapping
   7ffff7141000-…, lite libc.so.6 single R+E seg @vaddr0) = the instr right AFTER
   the `syscall` in `__internal_syscall_cancel` (objdump: `6e75c: syscall / 6e75e:
   leave`). So NOT a pure-userspace loop — hwdb hammers a cancellable syscall that
   returns instantly (stime rounds to ~0). With the task dump's last_syscall=write
   nsysc=15952 → **write() returns 0 on hwdb's output fd**, so glibc's write-all
   loop `while(left){n=write();left-=n}` with n==0 spins forever. FIX = find the fd
   type hwdb writes hwdb.bin (or its stdout/pipe) to and stop write() returning 0
   for a non-zero request (must write, block, or error). CONFIRM the exact
   syscall+fd+retval with `features=debug-all` filtered to hwdb's tid, or test
   writes to the same fd type in the debug-shell. **This likely also explains the
   general boot crawl** (any service hitting the same write-0 path).
   **DEFINITIVE ROOT CAUSE (2026-07-09f): hwdb serializes a corrupt/UNBOUNDED trie
   to an ext4 O_TMPFILE forever.** [HWDBWR] trace of hwdb's steady-state writes:
   `fd=3 type=0(regular) cnt=1024 n=1024 path="/" b=[binary trie bytes]` — 1024-byte
   binary chunks to an anonymous O_TMPFILE (path renders "/" = the hwdb.bin output
   opened O_TMPFILE in /etc/udev). Each write fully SUCCEEDS, yet it runs 60+s ≫ the
   13.5MB output → the trie being written is UNBOUNDED/CIRCULAR. So the write+ext4
   path is fine; hwdb built a corrupt trie earlier (read phase, lastsc=0). **ROOT is
   UPSTREAM of the write:** a bad input read / getdents / malloc made the trie
   circular. **NEXT: trace the READ/getdents phase** (fd + retval + bytes for tid's
   read/getdents before it flips to write) — did a read return wrong bytes or a
   getdents loop/dup? Likely ties to the ext4 read side (cold-read was already ~2.7
   MB/s) or a memory/malloc bug. Fix that → trie is finite → hwdb finishes → sysinit
   proceeds → getty.
   **XSAVE/AVX FIX ATTEMPTED → DISPROVEN for hwdb + has a corruption bug
   (2026-07-09l, branch F697-x86-xsave-xstate, NOT merged).** Found the FPU
   context-switch uses FXSAVE only (x87+SSE), never XSAVE — so AVX YMM / AVX512
   ZMM upper state is dropped across a switch (a real Linux-compat gap; fpu.rs
   comment admits it). Hypothesis: glibc AVX memcmp/strcmp corrupt mid-loop →
   hwdb trie dedup fails → bloat. Implemented XSAVE/XRSTOR + CR4.OSXSAVE + XCR0
   (x87|SSE|AVX only; AVX512 excluded — glibc falls back via xgetbv) in
   fpu.rs/regs.rs, bumped ARCH_FPU_SIZE. RESULT:
   - **hwdb STILL spins with AVX-XSAVE on → the SIMD-corruption hypothesis is
     DISPROVEN.** The trie bloat is NOT from unsaved AVX state.
   - **The implementation itself REGRESSES: intermittent BTreeMap memory
     corruption** ([PANIC] btree navigate.rs:534 / node.rs:1232, ~1 boot in 3;
     ARCH_FPU_SIZE=4096 → deterministic clone panic, =1088 → intermittent).
     Root: the FPU buffer is embedded BY VALUE in `Task` (`fpu_state:
     UnsafeCell<ArchFpuBuf>`), so growing it + align(64) either bloats the
     by-value Task on the kernel stack or perturbs the align-64 heap alloc →
     corrupts adjacent allocations. **Correct redesign: heap-allocate the FPU
     save area (`Box<align-64 area>`), keeping Task small/low-align; size the
     area from CPUID.0Dh:EBX; verify over N boots + both arches.** F697 is WIP,
     pushed, NOT merged (main stays known-good). Do not merge as-is.
   **hwdb root cause REMAINS OPEN.** Disproven this session: ext4 read/write,
   kernel allocator (brk/mmap/mremap/find_hole), AVX/SIMD ctxsw state. Confirmed:
   CPU-bound recursive `trie_store_nodes` serialization (libsystemd-shared
   0xd8150) over a too-large trie. Next hypotheses to probe: a non-SIMD
   userspace/libc miscompare in the trie build dedup, or a getdents/readdir
   double-count feeding hwdb duplicate entries. Also real gaps found:
   /proc/<pid>/{maps pathnames,syscall,wchan,fdinfo} stubbed; task comm not
   updated on exec.

   **★ LOOP PINNED (2026-07-09k): systemd `trie_store_nodes` recursion.** Built a
   user-stack backtrace probe in sys_write ([HWSTK]/[HWCALL], debug-wakelat, tid
   4135), modeled on 024_sched_yield's YIELD-SPIN symbolizer: it walks hwdb's user
   stack and prints (ino, file-offset) for each return address in a File-backed EXEC
   VMA. The spin stack (bottom→top):
     libsystemd-shared-257.so 0xd8150 (RECURSIVE, ~15-20 frames, offset 0xd8332
       repeats) → fwrite@plt → libc fwrite → _IO_file_xsputn → _IO_do_write →
       _IO_file_write → __write → syscall.
   objdump of 0xd82f0-0xd83a0 CONFIRMS 0xd8150 = **`trie_store_nodes`**: a
   `for i in 0..node->children_count` loop (cmp %rdx,%r15 @0xd836c) that `call
   0xd8150`s recursively per child (@0xd832d, ret→0xd8332) then `fwrite`s the node
   (16-byte child entries @0xd8390). So the blocker IS hwdb's recursive trie
   serialization. It's CPU-bound (fwrite buffers in glibc; neither ext4 write path
   fires during the 60s spin) → the trie has FAR too many nodes. Build grew brk to
   28MB (real Linux dedups the same 9.3MB input to ~5MB) → **the trie is degenerate
   (~5-6× too many nodes) because build-time prefix DEDUP failed** → trie_store_nodes
   walks a bloated tree for 60s+ → single-CPU starvation → boot never reaches getty.
   **NEXT (the actual fix): the build-side dedup.** hwdb `trie_insert`/node-match
   compares string bytes (memcmp/strcmp) to merge common prefixes; on our system it
   under-merges. Suspect a glibc SIMD memcmp/strcmp IFUNC mis-selected under our
   CPUID (or a subtle wrong result). Trace hwdb's memcmp/strcmp results, or add a
   trie-node COUNT probe (how many trie_store_nodes calls = node count; if ≫ real
   Linux, dedup is the bug). ALSO a real gap surfaced: **/proc/<pid>/maps returns NO
   pathnames** (broke every maps query) + /proc/<pid>/{syscall,wchan,fdinfo} stubbed
   — implement these (Linux-compat + unblocks future userspace debugging).

   **EVERY KERNEL ALLOCATOR PATH EXONERATED (2026-07-09j):** traced hwdb's brk
   growth ([HWBRK], since reverted): heap starts 0x10005000, cap 0x14005000 (the
   64MB load.rs HEAP_RESERVE). hwdb's brk grows steadily +4MB/step to 0x11be2000
   (~28MB in) then STOPS — never DENIED, never near the 64MB cap. So (a) the 64MB
   heap-cap is NOT the trigger, and (b) the whole 28MB trie lives in the brk heap →
   glibc never needed mmap arenas → **mmap/mremap are not even used for the trie**.
   Combined with find_hole (hole.rs) being correct on inspection, EVERY inspectable
   kernel allocator path is clean: brk grows fine, mmap/mremap unused, ext4 read/
   write correct, output bounded. The build completes normally (brk stops at 28MB at
   t≈14.7s) THEN the userspace serialize-spin begins (t≈15s, lastsc=1, bounded
   512KB output, <30000 syscalls in 110s = COMPUTE-bound not syscall-bound).
   **Only two suspects remain, both hard:** (1) the deep COW/rmap anon fault-fill
   (handle_page_fault_cow_rmap) hands hwdb an aliased/non-zeroed brk frame — but
   that machinery is broadly exercised and a bug would corrupt EVERY process, and
   the rest of the boot is fine, so unlikely; (2) a genuine hwdb/glibc userspace
   bug our env triggers via some subtle syscall-result difference. Distinguishing
   them REQUIRES seeing hwdb's userspace loop, which the gdb-can't-stop-the-spin +
   stubbed-/proc walls block. **The real unblock is a working userspace-disasm path:
   a gdb breakpoint with a large ignore-count (boot paused → break sys_write →
   continue → clean stop mid-spin, no async interrupt) to read the syscall frame's
   saved user RIP/RSP and name hwdb's caller; OR implement /proc/<pid>/{maps,syscall,
   wchan,fdinfo} for real so the debug-shell can introspect the spinning task.**

   **BIG CORRECTION (2026-07-09i): hwdb's output is BOUNDED (~512KB), NOT an
   unbounded/circular trie filling RAM.** A [FCSIZE] probe in framecache
   `write_buffered` (logs any buffered file crossing an 8MB boundary) stayed SILENT
   for a full 98s while hwdb (tid 4135) spun at `write()` (lastsc=1, rip
   0x7ffff71af75e = __internal_syscall_cancel). No framecache file ever exceeds 8MB;
   the only growing file is ino 9521 stuck at 512KB, re-flushed span=0. So the
   "unbounded/circular trie fills 2GB RAM" narrative (2026-07-09f) is WRONG — hwdb
   is in an INFINITE LOOP writing a BOUNDED ~512KB file forever. Since old [HWDBWR]
   showed write() returning n=1024=cnt (full success), glibc loop_write advances
   correctly → the loop is in hwdb's OWN outer logic (a bounded circular node
   traversal, or a write-verify-retry cycle), NOT a write-returns-0 and NOT an
   allocator-produced-unbounded-structure. The allocator-corruption theory is
   WEAKENED (a bounded loop needn't be memory corruption at all).
   **TOOLING WALL (why not yet pinned): can't see hwdb's userspace loop.**
   gdb can't stop a 100%-spinning KVM guest (qemu_interrupt/regs wedge); under TCG
   the interrupt also wedged. /proc/<pid>/{fdinfo,wchan,syscall,stack,maps-via-shell}
   are stubbed or the starved debug-shell has no awk. So the exact hwdb loop is not
   yet disassembled. **UNBLOCK OPTIONS (next session):** (a) gdb clean STOP via a
   pre-set breakpoint on `sys_write` with a large ignore-count (boot paused → break →
   continue → stops mid-spin without async-interrupt) → read the syscall frame's
   saved user RIP/RSP → name hwdb's caller; (b) a kernel trace of tid-4135 write()
   fd+file-offset+count (does the offset cycle 0..512KB [circular traverse] or stay
   fixed [retry]?) — distinguishes the two loop shapes; (c) implement
   /proc/<pid>/{fdinfo,syscall,wchan} for real (a genuine gap regardless). The
   write-offset trace (b) is the cheapest decisive next measurement.

   **CORRUPTION SOURCE NARROWED to in-memory build (2026-07-09h) — ext4 fully out:**
   Two independent disproofs this session localize hwdb's unbounded/circular trie to
   its OWN in-memory build (a kernel MEMORY-ALLOCATOR bug), NOT any fs path:
   (a) ext4 READ correct — guest sha256 of the 3 largest hwdb.d inputs (incl. the
       4.1MB 20-pci-vendor-model.hwdb) MATCH the host byte-for-byte.
   (b) ext4 WRITE not involved — with a [WAEXT] probe in `write_at_inner` (ext4
       debug-wakelat), the whole hwdb write-spin phase (both KVM & TCG boots) emits
       ZERO write_at events for hwdb's inode. hwdb's writes land in the buffered
       frame cache (O(1), no disk) — the spin is NOT the ext4 append/writeback path.
   Phase structure (TCG [USERIP] tid=4135): ~23-27s = varied RIPs, lastsc=0 (real
   read/build work, finite); then ~28s onward LOCKS to RIP 0x7ffff71af75e lastsc=1
   = __internal_syscall_cancel (the write() wrapper, per below) serializing forever.
   So: build completes → produces a CYCLE → serialize hammers write() unbounded →
   buffered into RAM → single-vCPU starvation → all services get 0.5-15s [WLBLK]/
   [WLLAT] stalls → boot never reaches getty (console+gnome both blocked).
   **NEXT (the fix): find the kernel allocator bug that corrupts a large userspace
   allocation into an aliased/overlapping region** (mmap address-picker overlap,
   brk/heap, or an mmap-of-many + free + remap reuse). Cheapest: a HOSTED test of
   the user-AS mmap allocator (many map/unmap/remap, assert no two live regions
   overlap); or a kernel trace of hwdb's mmap RETURNS checked for overlap (the
   [HWMMAP] probe, un-capped, correlated to a live-VMA set). Prior art: the
   MAP_SHARED|ANON COW-split-on-fork bug (memory index) shows this class is real.

   **ext4 READ RULED OUT (2026-07-09g):** guest sha256 of the 3 largest hwdb.d
   inputs (incl. the 4.1MB 20-pci-vendor-model.hwdb) MATCH the host byte-for-byte
   (0c4708…/bf7886…/334e55…). So ext4 read returns correct bytes even for a 4MB
   file → the trie corruption is NOT a bad read. With writes fast+buffered (O_TMPFILE
   uses wrap_file→framecache) and CPU/mem-ops normal, yet output unbounded (>200s ×
   ~11k writes/s ≈ GBs ≫ 13.5MB) → **prime suspect is a kernel MEMORY bug
   (mmap/brk/realloc) corrupting hwdb's large trie into a cycle** during the build.
   Other large-allocating userspace (GNOME) would hit the same. **NEXT: trace hwdb's
   mmap/brk/munmap** (addrs+lens) for overlaps/reuse-while-live, or a hosted mmap/brk
   stress test of large + realloc patterns. (disprove-don't-hack: ext4-read theory
   killed by the hash match.)

   **ALSO CONFIRMED BUG: task `comm` is never updated on exec** (kernel task.name +
   /proc/<pid>/comm both stay "fork-child"). Real Linux-compat gap; fix in the exec
   path (set comm to the new binary basename). It's why name-based diag filters fail.

   **(superseded) hwdb makes SUCCESSFUL write() syscalls in an infinite loop.** [USERIP]+lastsc: tid=4135 starts `lastsc=0` (read, ~10-11s
   reading input) then LOCKS `lastsc=1` (write) for 60+s at rip 0x7ffff71af75e =
   libc `__internal_syscall_cancel` FAST-PATH post-`syscall` return (objdump). The
   write neither returns 0 (`[WRITE0]` silent) nor errors (`[WRITEERR]` silent for
   hwdb) → each write SUCCEEDS. Target is a pipe/socket DRAINED by journald (tid
   4123 wakes constantly in [WLBLK]) — no output file, no backpressure. So hwdb
   isn't blocked; it's genuinely writing forever. Most likely mechanism: the read
   phase got bad/premature-EOF data → hwdb built a CIRCULAR/corrupt trie → the
   serialization walk writes forever. **NEXT: full arg-trace** (features=debug-all,
   filter hwdb tid) to see write(fd,buf,len) target + the read() that preceded it
   (did a read return 0 early / wrong bytes?), or read hwdb's source. Suspect the
   read/EOF path (ties to the ext4 cold-read slowness + a possible premature-EOF).
   **INCIDENTAL BUG FOUND: write to `/proc/pressure/memory` returns EINVAL(22)** for
   systemd PSI threshold setup (init + several children) — a real /proc PSI-write
   gap, separate from hwdb.
   Diagnostics landed (all debug-wakelat-gated, zero-cost off): `[USERIP]`+lastsc,
   `[WRITE0]`, `[WRITEERR]`.

   **UPDATE: NOT plain write().** Added a `[WRITE0]` trace in sys_write (Ok(0) on a
   non-zero request, debug-wakelat) — it NEVER fired while hwdb spun. So the looping
   cancellable syscall is NOT the `write` slot: it's another cancellation-point
   syscall returning instantly in a retry loop — `writev`/`ppoll`/`pselect`/
   `sendmsg`/`nanosleep`/`fsync` etc. (the task dump's `last-sysc=write` was likely
   stale). **NEXT: name the exact syscall** — boot `features=debug-watchdog,debug-
   wakelat`, at the spin read the `[sysrq] task dump` `last-sysc` column for tid=4135
   (auto-dumps on no-progress), OR add a rate-limited syscall-nr trace in the syscall
   dispatch filtered to the spinning tid. Then fix that syscall's return-0/instant
   path (must make progress, block, or error — not return a value that spins the
   glibc cancellable-syscall retry). Two reusable diagnostics landed: `[USERIP]`
   (C103) + `[WRITE0]` (this change).
   NOTE the earlier "infinite userspace loop / mem-cache / write-0" framings were
   each WRONG — corrected step by step by [USERIP]+objdump+[WRITE0] (disprove-don't-
   hack).

   **(prior localization) hwdb spins at a FIXED user RIP `0x7ffff71af75e`** for
   100+s straight — captured by a NEW `[USERIP]` sampler I added to the timer ISR
   (arch-irq lapic/dispatch.rs, gated `debug-wakelat`: reads user rip from IRQ
   frame+88, rate-limited). Boot with `features=debug-wakelat` → `[USERIP rip=...
   tid=4135 ...]` repeats the same rip = the spin site. It's in libc/libsystemd
   (0x7ffff7... region), a userspace busy-WAIT loop (NOT the vDSO — init's hot rip
   0x7ffffe71f75e is a different offset). init/journald do NOT spin (they block+wake
   every ~500ms — see [WLBLK]); only hwdb is stuck.
   **NEXT (to name the function):** boot debug-wakelat, at the spin `cat
   /proc/<hwdb-pid>/maps` (find pid via `grep -la hwdb /proc/*/cmdline`) BEFORE
   systemd kills hwdb at its 90s timeout; compute `0x7ffff71af75e - libbase`; then
   `objdump -d` that library (from ../images) at the offset. That names the exact
   busy-wait (likely a clock/futex/timeout spin) → then fix the kernel syscall/clock
   whose wrong return traps the loop.
   **Also:** init+journald block/wake on a ~500ms cadence (`[WLBLK] waited_us≈500000
   ready=1`) — looks like a 500ms poll timeout instead of event-driven wakeups;
   likely the epoll-wake latency issue (B678 area) — a SECOND contributor.

   **SEPARATE perf bug found: ext4 COLD-READ is slow (~2.7 MB/s)** — 13.5MB took 5s
   cold, ~1s cached. Contributes to the general boot crawl (every service reads
   files cold). Real ext4 (goal-2) perf item; not the hwdb loop but stacks with it.
2. **Later stall: sysusers/userwork exit → zombies unreaped ~45s** while init/userdbd
   sleep in epoll_wait. B678 targets this (reap-wake gen race). Unverified because
   #1 blocks first.
3. Earlier debug-boot run also showed a userdb varlink stall (tmpfiles↔userdbd,
   userwork idle in ppoll) — may be same root as #2.

## /proc bugs found (real, separate, worth fixing)
- `/proc/<pid>/syscall` always returns `running` (never the blocked syscall) —
  breaks `has_zombies`-independent diagnosis. Stub/broken.
- `/proc/<pid>/comm` not updated on exec (stays `fork-child`). Cosmetic but wrong.

## qemu MCP recipe (WORKS this session — use it)
- `qemu_start(arch=x86_64, accel=kvm, features="debug-watchdog", paused=false)` —
  builds+boots; clean klog so the serial debug-shell is readable.
- Image: `../images/output/live-gnome-x86_64-root.img` is a symlink → lite (I made
  it so the MCP's default profile boots; the images repo hasn't built live-gnome).
- `qemu_run_until(pattern, timeout)`, `qemu_send_serial`, `qemu_serial(clear=True)`,
  `qemu_screen`. Serial task dump: SYSRQ_ARM=0x00 then 't' — but I couldn't send a
  raw NUL via qemu_send_serial; `/proc/sysrq-trigger` is EROFS (not wired). The
  debug-boot watchdog auto-dumps tasks (`[sysrq] task dump`) on no-progress — that's
  how I got the ST/last-syscall table. **image has NO awk, NO ps** — use /proc + sh.

## First task next session
Root-cause the `systemd-hwdb update` userspace spin (front blocker). Options:
(a) run gdb with hwdb's userspace symbols (or catch RIP by interrupting BEFORE the
spin starts — break early, single-step into the loop); (b) boot `features=debug-all`
and grep the syscall trace for hwdb's tid to see the LAST syscalls before it stops
syscalling (what it read/mmapped/configured); (c) test the hypothesis that a
specific libc call (getline/mmap/qsort/nss) returns wrong data by running a minimal
repro under the debug-shell. Once hwdb finishes, re-verify B678 clears the reap
stall and whether getty.target is reached.
