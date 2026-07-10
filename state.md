# state — live-gnome boot (Goal 3)

Branch: `main` (clean). BREAKTHROUGH this session: the multi-session ~55s heap-corruption
blocker is ROOT-CAUSED and FIXED (B712). Boot now advances past it.

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
  1. **Residual, RARER second corruptor** — one own-qemu boot still #UD'd at 52.9s in
     `resolve_mount+4751` = handle_alloc_error (a Vec grew to a HUGE capacity → a LARGE-value
     write, UNLIKE B712's write-0 → likely a SECOND UAF, not the on_cpu one). Post-B712 the
     MCP boot instead reached 58.6s (no crash). So B712 fixed the dominant case; a rarer
     writer remains.
  2. **Busy-spin at ~58.6s** (after sshd-keygen@ed25519 Finished) — 94.9% CPU, IRQs-off
     (gdb async-break + qemu_interrupt both fail to stop it) = a spinlock livelock. Reached
     only when the corruption is avoided. Likely a known stall blocker now exposed
     ([[hwdb-blocker-ext4-writeback-commits]] / [[desktop-blocker-tmpfiles-userdbd]]).

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
Re-run the v6-loop forensic on a fresh (post-B712) build to capture the RESIDUAL #UD's
corrupt object + neighbors (identify the 2nd writer), OR attack the ~58.6s busy-spin (needs
a way to stop the IRQ-off spin — e.g. hw breakpoint on the suspected spinlock, or add a
non-perturbing klog in the spin path).

NOTE: a stray own-qemu (scratchpad/wp) may still be running — ask user to `pkill -9 qemu-system`
if boots foul. Uncommitted diag: kalloc poison.rs (other lane) + Cargo.toml (feature-gated off).
