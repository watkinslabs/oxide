# 11 VMM

FROZEN 2026-05-02. Dep:`01`,`02`,`06`,`08`,`09`,`10`,`14`,`20`,`21`. Provides: every process; backs `mmap`/`mprotect`/`munmap`/`mremap`/`madvise`/page-fault/`fork`.

Per-process AS, install/remove translations, demand-fault, COW fork, file mmap. Doesn't manage phys (`10`) or kernel mem (`12`).

## 1 Inputs/outputs

- Deps: PMM (frames), HAL `MmuOps` (PTE+TLB), `06` (RwLock).
- Provides: `AddressSpace`; mmap/munmap/mprotect/mremap/madvise; page-fault handler.
- HW: PT, TLB via HAL.

## 2 Frozen invariants

1. Non-overlap: VMAs in AS cover disjoint ranges.
2. PTE-VMA agreement: present PTE perms P over VA V ⇒ VMA covering V perms ⊇ P. PTEs may be more restrictive (COW write-protect).
3. W^X user: no PTE has both W and X in user space at quiescence.
4. Canonical-only user: user PTEs point at `UserVirtAddr`.
5. Kernel mapping: higher-half identical in every AS (shared kernel PML4/PGD entries).
6. TLB safety: unmap or perm-reduce completes before next user instr that could observe old translation. Implemented: TLB flush before lock release.
7. COW soundness: private writable VMA's PTE write-protected if phys page refcount>1. Write-fault: copy first, then upgrade PTE.

## 3 Public ifc

```rust
pub struct AddressSpace { /* ... */ }
impl AddressSpace {
  pub fn new() -> KR<Arc<Self>>;
  pub fn fork(&self) -> KR<Arc<Self>>;                                 # COW clone of private VMAs

  pub fn mmap(&self, hint:Option<UVA>, len:usize, prot:u32, flags:u32,
              file:Option<&Arc<File>>, off:u64) -> KR<UVA>;
  pub fn munmap(&self, addr:UVA, len:usize) -> KR<()>;
  pub fn mprotect(&self, addr:UVA, len:usize, prot:u32) -> KR<()>;
  pub fn mremap(&self, old:UVA, old_len:usize, new_len:usize,
                flags:u32, new:Option<UVA>) -> KR<UVA>;
  pub fn madvise(&self, addr:UVA, len:usize, advice:i32) -> KR<()>;

  pub fn handle_page_fault(&self, va:UVA, fault:FaultKind) -> KR<()>;

  pub fn copy_from_user(&self, dst:&mut [u8], src:UVA) -> KR<()>;
  pub fn copy_to_user(&self, dst:UVA, src:&[u8]) -> KR<()>;
}
```

## 4 VMA tree

```rust
struct Vma {
  range: Range<UVA>,
  prot: VmaProt,            # R W X
  flags: VmaFlags,          # SHARED|PRIVATE|ANONYMOUS|GROWSDOWN|LOCKED|...
  backing: VmaBacking,      # Anonymous | File{Arc<File>,off} | Special(vDSO|vvar|hugetlb)
  rss: AtomicU64,
}
```

`BTreeMap<UVA,Vma>` keyed by start; RwLock-protected. Lookup O(log N). Insert may split or merge adjacent compatible VMAs (same prot/flags/backing/contig-offset).

## 5 Page fault

```
handle_page_fault(as, va, fault):
  vma = as.vmas.read().find(va)?
  if !vma.permits(fault.access): return Err(EFAULT)        # SIGSEGV upstream
  match fault.kind:
    NotPresent =>
      frame = match vma.backing:
        Anonymous     => pmm.alloc(0)?                      # zero-fill on first touch
        File{f,off}   => pagecache.get_or_read(f, off+(va-vma.start))?
      zero_or_loaded(frame); mmu.map(va, frame, vma.prot.to_pte_flags())
    Write && pte.present && !pte.writable =>                 # COW
      if frame.refcount() == 1: mmu.upgrade_writable(va)     # sole owner; flip W
      else:
        new = pmm.alloc(0)?; copy_page(new, pte.frame())
        frame.dec_ref(); mmu.replace(va, new, writable)
    _ => kassert!(false, "unhandled fault kind")
```

PF holds VMA tree read lock. PT mutated under per-AS PT spinlock (class `PageTable` < `AddressSpace`).

## 6 mmap/mprotect/munmap

- mmap: find hole (or `MAP_FIXED`/`MAP_FIXED_NOREPLACE`), build Vma, insert. Lazy unless `MAP_POPULATE`.
- mprotect: walk affected VMAs, split at boundaries, change `prot`, walk PTEs to demote (never upgrade in mprotect — lazy on fault).
- munmap: remove VMAs in range, walk PTEs to unmap, free pages whose refcount drops to 0, broadcast TLB shootdown.

TLB shootdown:
1. Target CPU mask = every CPU whose `current.mm == self`.
2. IPI those CPUs with (va, len).
3. Local flush.
4. Wait IPI acks (counter).
5. Release PT lock.

## 7 fork (COW)

```
fork(self):
  new = AS::new()?
  vmas = self.vmas.read(); new_vmas = new.vmas.write()
  for vma in vmas:
    copy = vma.clone_cow(); new_vmas.insert(copy)
    if vma.flags.contains(PRIVATE):
      for pte in self.pt.walk(vma.range):
        pte.write_protect(); pmm.frame(pte.frame).inc_ref()
        new.pt.set(pte.va, pte.frame, pte.flags & !W)
    else:                                                    # SHARED
      for pte in self.pt.walk(vma.range):
        new.pt.set(pte.va, pte.frame, pte.flags); pmm.frame(pte.frame).inc_ref()
  self.flush_tlb_self()                                      # parent PTEs changed
  Ok(Arc::new(new))
```

`pmm.frame(pte.frame).inc_ref()` requires per-page metadata array — resolved here: PMM ships `struct page`-equivalent sized by max PFN.

## 8 Per-page metadata

```rust
struct PageMeta { refcount:AtomicU32, flags:AtomicU32, mapping:AtomicPtr<MappingId> }
static PAGE_META: &[PageMeta]   # len = pfn_max - pfn_min + 1; ~16B/page ≈ 0.4% RAM
```

Flags: DIRTY, REFERENCED, LOCKED, RESERVED, …. mapping: shared/file pages → `(Inode, off)`. Allocated by PMM at boot.

## 9 Concurrency

- Per-AS `RwLock<BTreeMap<...>>` class `AddressSpace`.
- Per-AS PT `Spinlock<PageTable>` class `PageTable` (< `AddressSpace`).
- TLB shootdown acks via per-CPU atomic counter.
- PF takes VMA read; mmap/munmap/mprotect take write.
- v1.x: RCU + per-VMA locks for hot PF path.

## 10 Perf budget

| Op | p99 cy |
|---|---|
| PF anon zero-fill | 3000 |
| PF COW refcount=1 | 1500 |
| PF COW real copy | 5000 |
| `mmap` 4p anon | 4000 |
| `mprotect` 4p demote (incl TLB shootdown) | 5000 |
| `munmap` 4p (incl TLB shootdown + free) | 6000 |
| `fork` 1000-VMA 100K-page | 200000 |

## 11 Test contract (frozen)

- Hosted unit on fake `MmuOps` recording ops; mmap/munmap/mprotect produce expected sequences.
- Property: random {mmap,munmap,mprotect,fault} sequences; verify invariants 1,2,3 vs interval-list oracle.
- QEMU integration: userspace maps anon, files, fork+exec, mprotect, munmap; 1h; no panic, no leaked frames.
- Soak (bg, not gate per `40§3`): 4h cycles `stress-ng --vm` 4-CPU SMP; final unmount + munmap-all + zero leaked frames. PR-time gate uses `paranoid-ci` (`debug-vmm` audit per op).
- Power-cut symmetry test: kill QEMU during heavy mmap/munmap; reboot clean (no on-disk VMM state).

## 12 Failure modes

- VMA invariant violated in `debug-vmm` audit: panic.
- PT walk hits PTE w/o VMA: panic (kernel bug; user can't cause).
- TLB shootdown timeout (peer no ack in 1s): panic w/ peer state.
- ENOMEM during fault: SIGBUS to userspace; no panic.

## 13 Debug

`debug-vmm`: VMA tree audit per op; PT walker invariants per op.

## 14 Log

`target="vmm"`, `"vmm::tlb"`, `"vmm::fault"`. trace=per-fault (debug only); debug=mmap/munmap/mprotect; warn=TLB shootdown timeout retry; error=invariant.

## 15 Cross-spec

`10` (frame alloc), `06` (locks/RCU), `15§6.2` (mmap flags), `27§11` (W^X), `30` (io_uring fixed buffers pin pages).

## 16 Changelog

(none)

