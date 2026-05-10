# State 2026-05-10 (session 5)

## Branch

`F156-mm-linux-conformance` — PR #920 against `main`. HEAD = `59a8265`.

## Now working end-to-end on BOTH arches

- **x86_64**: login → `/bin/echo HELLO_RMAP` round-trips through fork
  + COW + execve with rmap wired into PageMeta. No panics.
- **aarch64**: init forks (sys_clone child_tid=4096), child reaches
  post-fork execve cleanly. No SIGSEGVs in the cascade.

1034 hosted tests passing, spec-lint clean.

## What landed (59a8265)

### arm boot fix

`elf_smoke_arm::spawn_init_from_rootfs_arm` was using a 4 KiB stack
at low VA 0x501000. busybox+musl's fork frame walked off the bottom
into 0x500f70 → SIGSEGV. Fixed by:
- new `INIT_STACK_LEN=0x10000`, `INIT_STACK_VA=USER_VA_END-0x20000`
  (matches x86 layout)
- pre-fault every stack page from the boot path so kernel-side
  `build_user_stack` writes don't take EL1 same-EL data aborts
  (boot fault handler routes to GLOBAL AS, not the per-task mm we
  just activated)

### kernel-side rmap wiring

`vmm::AnonVma` is now reachable from a frame's `PageMeta.mapping`:

- **`pmm::PageMeta`** — gained `page_index: AtomicU32` + helpers.
  Slot size 16→24 B (within the <1% RAM overhead budget).
- **`pmm_setup`** — Linux-shape adapters that own the
  `Arc<AnonVma>` ↔ raw-pointer dance:
  - `set_anon_rmap_for_pa` (≡ `page_add_anon_rmap`)
  - `clear_anon_rmap_for_pa` (pre-`__free_pages`)
  - `anon_vma_for_pa` / `page_index_for_pa`
  - `rmap_aware_dec_and_maybe_free` (clear-then-dec wrapper)
- **`vmm::AddressSpace::handle_page_fault_cow_rmap`** — the
  rmap-aware COW + demand-page handler. Calls
  `set_rmap(pa, &Arc<AnonVma>, page_index)` on every successful
  frame install (wp_page_copy split + Anonymous demand-page).
  Plain `handle_page_fault_cow` is now a thin no-op-rmap wrapper
  so hosted tests don't change.
- **`kernel::user_as::do_handle`** routes through the rmap variant,
  passing the kernel adapters. Every demand-faulted anonymous
  page now records which AnonVma family it belongs to.

`rmap_walk_anon` is now a real working API end-to-end: given a PA,
walk the AnonVma chain to enumerate every (mm, va) pair the page
COULD be at. Linux migration / KSM / OOM-pageout machinery has
the foundation it needs; the consumers themselves are out of
F156 scope.

## Open / next session

1. **arm interactivity** — boot reaches login + child execve, but
   keystrokes after the prompt aren't reaching busybox (looks like
   an arm tty/getty wiring issue, not memory). Test with the
   /bin/echo round-trip path that works on x86.
2. **rmap consumers** — `rmap_walk_anon` exists; nothing yet
   walks it. Candidates: page-out scaffolding, KSM probe, or the
   `/proc/<pid>/smaps` "shared/private" accounting columns.
3. **File-backed rmap** — `address_space->i_mmap` interval tree
   for shared file mmaps. Currently every VMA with KernelBytes
   backing has `anon_vma=None`; that's fine for v1 (we don't
   share file pages across AS yet) but Linux uses a separate
   data structure for file rmap.
4. **Hierarchical anon_vma** — Linux's child anon_vma rooted at
   parent. Saves walks on child-only pages. Pure optimization.
5. **Swap, KSM, NUMA** — out of v1 scope.

## First task next session

```
cargo run -p xtask -- qemu --arch aarch64
# observe: arm reaches `oxide login:` and forks, but typing root
# doesn't progress past the prompt. Likely a getty / tty / line-
# discipline mismatch — child is alive (clones, opens, execs) but
# stdin doesn't bind to the serial chardev.
```
