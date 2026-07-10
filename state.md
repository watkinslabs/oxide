# state — live-gnome boot (Goal 3)

Branch: `main` (clean). B712 fixed the DOMINANT ~55s corruptor. ONE residual corruptor
remains (pointer-sized scribble, roving victim, ~50s) — it is the SOLE Goal-3 blocker: the
"~58s busy-spin" is DISPROVEN as independent (it's downstream of this same corruptor). Static
reading of every sched/exit/reap/ttwu/vfork path is exhausted; next step is a DYNAMIC catch.

## Landed this session (8 PRs)
- **B712 (#2951)** — THE big one: scheduler switch-tail UAF. `oxide_finish_task_switch`
  drop()d a self-reaping non-leader thread (tid!=tgid) from `reap_pending` BEFORE
  `finish_switched_from` wrote `(*switched_from).on_cpu.store(false)`. `schedule()` puts the
  SAME outgoing task in both slots, so on a non-leader exit the raw `on_cpu` write hit a
  freed+reused `Task` — scribbling `0`/small values into whatever object (BTree node, Vec
  buf, dcache Weak, VMA) reused the slot → the non-deterministic ~55s #UD/#PF in
  resolve_mount/d_lookup_reval/AddressSpace::find (all innocent victims). Fix: reorder —
  `finish_switched_from` FIRST (on_cpu=false while reap_pending's Arc keeps the task live),
  THEN drain+drop. Root-caused via a forensic own-qemu #UD-capture harness + user code-review.
- **B709 #2944** sb-root d_count pin, **B710 #2945** rseq fault-safe, **B711 #2950** kalloc
  IRQ-atomic — real adjacent/downstream fixes.
- **F698 #2948 / D207 #2949** — Goal 1 (console) 100%: DTB-sourced pl011 UARTCLK, zero divergences.
- Goal 2 (ext4) verified 100%: `cargo test -p ext4` + all 5 real-2.9GB-image diagnostics pass.

## Goal status
- Goal 1 console: DONE. Goal 2 ext4: DONE (verified). Goal 3 live-gnome: past the ~55s wall,
  two frontiers remain:
  1. **Residual, RARER second corruptor** — #UD at ~52s, `resolve_mount+4751` = a `ud2`
     immediately before `call handle_alloc_error` = a Vec **capacity-overflow / alloc-fail
     abort**. Forensic (own-qemu, caught 2/2 attempts) shows `rax` at a partially-built
     collection of SEQUENTIAL mount-ids 0xe..0x13 (14..19) → this is `mounts_in_ns`
     (`MOUNTS.lock().values().filter(ns).cloned().collect()`). So the `collect()`/`reserve()`
     got a HUGE size → a collection's len/cap (or the BTreeMap size_hint = MOUNTS.length) was
     scribbled to a huge/pointer value. LARGE-value write, UNLIKE B712's write-0 → a SECOND
     raw write to a freed+reused block. Post-B712 the MCP boot instead reached 58.6s (no
     crash), so B712 fixed the dominant case; this fires in a minority of boots.
     NEXT: (a) MOUNTS is a `static Spinlock<BTreeMap<u64,Arc<Mount>>>` — its `.length` field
     is at a STABLE static address, so a conditional hw watchpoint there (`if len > 0x10000`)
     could catch the writer despite the non-determinism; OR (b) audit sched/other for a raw
     write of a POINTER/large value to a reaped Task (B712 only covered on_cpu=0/false).
  2. **Busy-spin at ~58.6s** — DISPROVEN as a Spinlock livelock this turn (C109 #2954).
     Wired `--features debug-smp` through boot→kmain→sched+sync to expose the existing
     `[SMP-STALL]` probe (sched `smp_spin_warn` names any lock spinning >200M iters). A
     forensic debug-smp boot spun then #GP'd — NO `[SMP-STALL]` fired → NOT a Spinlock.
     The spin is `sys_exit.rs:156` / `terminate_current_with_signal` (zombies.rs:547)
     `loop{spin_loop()}` reached IFF a Zombie RETURNS from `schedule()`. DISPROVEN as
     reachable without prior corruption: ttwu rejects zombie wakes (ttwu.rs:178 state!=
     Runnable→false), `pick_next_task` returns idle NOT current (runqueue.rs:81), zombie
     current is never re-enqueued (switch.rs:236 needs Runnable). So a Zombie cannot come
     back from schedule() → BOTH the spin AND the #GP are DOWNSTREAM of the ONE corruptor.

## Corruptor — sharpened (this turn)
- debug-smp forensic boot: deterministic **#GP at ~50s in `vfs::poll_subs::PollSubscribers
  ::subscribe`**, faulting on `lock cmpxchg %r12b,0x18(%rdi)` (the embedded Spinlock CAS)
  with **`rdi`(self)=`0x8341b274db8548fd`** — a fully-garbage (non-canonical, not a partial
  HHDM-ptr scribble) pointer. id/wake args looked valid → caller loaded a stale/corrupt
  `&PollSubscribers` (roving victim; layout shifted by debug-smp vs the mount-collect victim).
- CONFIRMED **B712 switch-tail is complete**: `finish_switched_from` only writes `on_cpu`
  (bool 0/1); the residual writes a POINTER-sized value → a DIFFERENT writer, not the switch.
- Audited this turn, all correct on inspection: switch.rs full tail (fpu_save/ArchCtx::switch
  write prev BEFORE the switch while prev_arc/reap_pending pins it), ttwu claim-CAS, vfork
  parent-park (watch Arc pins parent across the wait), zombies enqueue/reap/park_for_wait4,
  terminate_current_with_signal (replace_mm(None) before CR3-switch — but SAME as sys_exit,
  would corrupt every exit if broken). Corruptor evades static reading across many sessions.
- CONCLUSION: next tool must be DYNAMIC. Victim roves per-boot so a fixed hw-watchpoint can't
  pre-target it. Best options: (a) poison quarantine-SCAN — poison MASKS the crash by delaying
  reuse but the corruptor STILL writes the freed(now-quarantined) block, so verify-on-scan of
  quarantined blocks catches the corrupted block + backtrace (needs the other lane's poison.rs
  or a fresh redzone-verify in KAlloc); (b) narrow to the ~50s window (gnome thread churn) and
  bisect which SUBSYSTEM's teardown fires then (epoll/inode close is implicated by the victim).

## Forensic harness (PROVEN, reuse it) — see [[gnome-blocker-refcount-uaf]]
Own-qemu (replicate the MCP device set: q35 -cpu host -enable-kvm -m 2G -smp 1, virtio-blk
root(fresh cp of ../images/output/gnome-x86_64-root.img)+home, virtio net/gpu/kbd/mouse,
-serial file, -monitor unix:sock, -gdb tcp::9999 -S). Catch #UD deterministically:
`hbreak *<oxide_vec_6 addr>` (the vector-6 IDT stub, hit ONLY on #UD, no boot crawl); at
the stop the live regs ARE the faulting Arc/Weak op (rdx=corrupt target). Loop up to ~10
boots (#UD is ~30-50%/boot). ALWAYS `set language c` (kernel ELF has no C types). Run
BACKGROUNDED (`nohup … &` + Monitor on a DONE marker) to beat Bash's 120s timeout; teardown
via `echo quit | socat - unix-connect:mon.sock` (voluntary qemu exit, safe vs can't-kill).

## First command next session
Build a DYNAMIC corruptor catcher (static reading is exhausted — every candidate path reads
correct). Fastest repro now: `mcp__qemu__qemu_start arch=x86_64 features=debug-smp` (KVM),
`qemu_continue` (times out at 120s = fine), then `qemu_serial` — the #GP dump lands at ~50s.
Then implement quarantine-verify-on-scan in KAlloc (catch the write to the freed block even
though the victim roves) OR window-bisect the ~50s teardown by subsystem.

NOTE: a stray own-qemu (scratchpad/wp) may still be running — ask user to `pkill -9 qemu-system`
if boots foul. Uncommitted diag: kalloc poison.rs (other lane) + Cargo.toml (feature-gated off).
