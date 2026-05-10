# State 2026-05-10 (session 4)

## Branch

`F156-mm-linux-conformance` — PR #920 against `main`. HEAD = `216fa7f`.

## What's working end-to-end (x86_64)

- `cargo run -p xtask -- qemu --arch x86_64` → login → fork+exec cycles hit
  COW remap on stack, **no kernel panic** (was `MmuOps::map walker failure`
  pre-216fa7f).
- 1034 hosted tests passing, 0 failing, spec-lint clean.

## What's new in this session (216fa7f)

1. **COW remap fix** in `hal-x86_64::mmu_ops::map` and
   `hal-aarch64::mmu_ops::map`: when the walker reports
   `WalkErr::AlreadyMapped`, route through `unmap_at_va` then re-call
   `map_at_level`. Linux-equivalent for the `wp_page_copy` shape that
   installs a freshly-allocated private PA over a previously-shared one.

2. **Full anon_vma + PageRmap subsystem** under `crates/vmm/`:
   - `anon_vma.rs` — `AnonVma` family with `RmapTarget` chain,
     attach/detach/walk/gc_dangling, `Weak<AddressSpace>` for
     auto-pruning of dropped AS edges.
   - `rmap.rs` — `PageRmap { mapping, page_index, mapcount }`
     per-page descriptor + `rmap_walk_anon` per Linux
     `mm/rmap.c::rmap_walk_anon`.
   - `Vma::anon_vma: Option<Arc<AnonVma>>` auto-allocated for
     `VmaBacking::Anonymous`; cloned through `clone` +
     `clone_subrange` so fork + mprotect-split keep family membership.
   - `AddressSpace::fork_cow_pages` attaches child mm-weak per
     anon VMA (Linux `anon_vma_fork`).
   - `sync::AnonVma` lock class at rank 25 (between PageTable=20 and
     AddressSpace=30).

3. **Tests** — 18 new hosted tests covering: pt_walker
   unmap-then-remap; anon_vma chain attach / walk / Weak filter / gc;
   PageRmap set/replace/clear/mapcount; rmap_walk_anon target
   enumeration; HostMmu-backed COW chain regression that pins the
   F156 fix in place.

## Open / next session — arm64 fork-ABI segfault

`cargo run -p xtask -- qemu --arch aarch64`: init reads inittab,
forks (`sys_clone child_tid=4096`), child runs ~10 syscalls then
SIGSEGVs at `far=0x500f70 elr=0x100f0e60` (busybox userspace code).
Three children spawn and die the same way; eventually init itself
segfaults. Fault address sits in busybox's stack region, suggesting
the post-fork user register save/restore on arm doesn't faithfully
hand the child's SVC-resume frame. Likely candidates:
- `hal_aarch64::ContextAArch64::new_user_for_fork` register slots
  off-by-one vs `oxide_irq_resume_user` asm
- `clone_spawn_arch` SVC-frame snapshot missing x18/x29/x30 sources
- TPIDR_EL0 / SP_EL0 wiring mismatch on first eret

First task next session: gdb-stub at child's first eret, dump x0..x30
+ ELR + SP, compare against parent's saved frame at sys_clone entry.

## Other gaps (not this commit)

- File-backed rmap via `address_space->i_mmap` interval tree.
- Hierarchical `anon_vma->root` (Linux trick to avoid walking
  child-only pages).
- Kernel `pmm_setup` injection of `PageRmap` into `PageMeta` so
  `set_anon_vma` / `clear_anon_vma` get called from demand-fault
  and munmap. Currently the data structures + tests live in vmm;
  the kernel-side wiring is the next layer.
- Swap, KSM, NUMA — out of v1 scope.
