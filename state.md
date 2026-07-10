# Handoff — live-gnome 246s-stall → 53s (5 fixes merged); final blocker = NAMESPACES BTreeMap wild-write

Goals 1+2 done. Goal 3: transformative progress — boot advanced from the
session-start 246s userdb-stall to ~53s (NetworkManager, accounts-daemon, rtkit,
sssd, nss-user-lookup.target all up), one heap-corruption fix from the graphical stack.

## Merged this session
- **B707/#2936** ext4 SMP metadata-transaction race (rootfs corruption during boot).
  The session-long ~55-65s #UD/Weak::upgrade "kernel UAF" was DOWNSTREAM of this.
- **B708/#2938** four fixes: (1) **ext4 gate deadlock** (B707 regression — busy-spin
  gate held across sleeping block I/O → CPU-STALL in truncate_inode; the
  "post-userdbd wakeup stall" was THIS; fixed with a yield hook →
  `sched::live::tick_yield`); (2) **SMP virtio #PF** (AP master-PML4 resync per MMIO
  splice in `mmio_map`); (3) **epoll per-epitem sub id**. All boot-verified: 26s→53s.
- **C108/#2935** debug-heappoison tool (off by default).

## FINAL BLOCKER (deterministic, precisely localized) — NAMESPACES BTreeMap corruption
At ~52.8-53.2s during NetworkManager/accounts-daemon path resolution:
`[FAULT] #PF NP-R-K rip=vfs::mount::resolve_mount cr2=0x11a` (and `#GP rbx=0x60` on
another boot — reproduced 2/2, deterministic).
DISASM PROVES it (objdump resolve_mount, fresh build): the loop is a **BTreeMap
traversal of `vfs::mntns::NAMESPACES`** (the mount-namespace registry,
`Spinlock<BTreeMap<u64, Arc<MntNamespace>>>`, mntns.rs:112). `resolve_mount` →
`current_ns()` → `ns_root_id()` → `NAMESPACES.get(id)` walks BTreeMap nodes; a node's
**edge pointer (offset 0xc0) is `0x60`** → traversing into it reads len at
`0x60+0xba = 0x11a` → the exact `cr2=0x11a`. So a NAMESPACES BTreeMap node is
CORRUPTED with the value 0x60.
- All NAMESPACES access is spinlocked + BTreeMap is std-correct → this is an EXTERNAL
  **wild-write / heap corruption** clobbering a ns-registry node (not a NAMESPACES
  logic bug; not caused by this session's changes — mntns untouched, newly reachable
  now the earlier blockers are gone).
- **KEY LEAD: `0x60 = 96`, and by ~53s systemd has created ~96 mount namespaces**
  (one per PrivateMounts service) → 0x60 is very likely a **ns-id (~96) written into a
  pointer slot** — a type confusion / wild-write of an id where a `*Node`/`Arc` goes.
- debug-heappoison boot was INCONCLUSIVE (poison shifted the failure to a 32s
  getdents64 idle stall — heap-layout-sensitive, consistent with a wild-write, but the
  [UAF] fault-probe didn't catch it since the write isn't a freed-block read).
- No obvious id↔ptr cast in mntns.rs/mount/*.rs (grepped `as *`/from_raw/transmute).

## ROUND 4 — ROOT CAUSE CAUGHT (non-perturbing): dentry d_count over-put in fd-close/File::drop
A non-perturbing probe (klog in `Lockref::put` when the result < 0 — klog does NOT
allocate, so heap layout is unchanged and the bug does NOT move) caught the ROOT,
DETERMINISTICALLY and EARLY (~21s, right after init spawn, long before the 53s crash):
- `[LOCKREF-UNDERFLOW] d_count@=ffffffff828efe90 now=0xffffffffffffff80` (= -128 =
  `LOCKREF_DEAD`). The address is inside `kalloc::STATIC_HEAP` → a normal heap dentry.
- A SPECIFIC dentry's `d_count` (Linux lockref, `dentry/lockref.rs`) is **over-put**
  (`put()` = `fetch_sub(1)-1`, NO underflow floor) → driven negative to `LOCKREF_DEAD`
  → the dentry reads as DEAD → the next `dget` (`lock incq; jg; ud2` in
  `dcache::alloc::d_lookup_reval`) #UDs, AND freed/reused dead-dentry memory corrupts
  adjacent heap (the NAMESPACES BTreeMap edge → the 53s `resolve_mount` #PF). ONE root,
  layout-dependent symptom.
- Stack scan + an int3 trap's fault regs (`rbx = FdTable::close`) place the over-put in:
  **`FdTable::close` → `Arc<File>::drop_slow` → `File::drop` → `dput(self.dentry)`**
  (`vfs/src/file/lifetime.rs:53`). `File::new_at` DOES `dget` (`file/model.rs:75`), so
  the imbalance is an EXTRA dput per open/close cycle on this dentry — a MISSING `dget`
  where the File's dentry is set, or a second dput in the close/flush/close-hook path.
  Audited & NOT the culprit: `d_unlink`/`d_delete` (no dput), `d_prune_aliases` (skips
  `d_count>0`), `free_orphan_inode` (pure ext4 metadata). int3 does NOT break into gdb
  (kernel #BP handler intercepts it).
- NEXT (final narrowing): boot, `watch *(long*)0xffffffff828efe90` after the dentry is
  first alloc'd (or set a gdb breakpoint at `dcache::lifecycle::dput` filtered to that
  dentry) → the caller of the EXTRA dput is the bug. Then fix (balance the dget/dput; and
  defensively floor `Lockref::put` / warn at 0→negative). This is the WHOLE live-gnome
  blocker chain's root.

## ROUND 3 — diagnosis (superseded by ROUND 4 above; kept for context)
A temporary NAMESPACES integrity probe (walk-the-map between each CLONE_NEWNS
sub-step in `apply_new_namespaces`; reverted) proved:
- **All 16 NAMESPACES checks PASS (`ok`)** under the probe's layout — NAMESPACES is
  NOT the primary victim; it's collateral. And only ~16 mount-ns exist by ~57s, so
  **0x60/0x38 are NOT ns-id 96** — they're garbage/refcount values. The round2.md +
  my earlier "ns-id-as-pointer" hypothesis is WRONG.
- The fault MOVED (probe changed heap layout) to a **`#UD` in `vfs::dcache::alloc::
  d_lookup_reval`**: `lock incq 0x8(%rdx); jg; ud2` with **rdx = a VALID live dentry
  ptr** (ffff8000…) — so a LIVE dentry's refcount word (offset 8 = Arc weak / d_count)
  is **over-decremented → negative**, and the next clone/downgrade aborts.
- ⇒ ROOT = a **Dentry/Arc refcount IMBALANCE (over-drop)** on SHARED dentries in the
  mount-namespace clone/dcache-churn path (snapshot_ns → copy_mnt_ns → clone_tree /
  dcache). It corrupts a small field (a refcount, or a BTreeMap edge) with a small
  value; WHICH object (NAMESPACES node vs dcache dentry) depends on heap layout.
  [[mount-dentry-sharing-gotcha]] (shared dentries across mounts/ns).
- **Every heap instrumentation perturbs it** (poison/quarantine → 32s stall; redzone
  → 35s stall; integrity probe → moved the victim to dcache). So the ONLY
  non-perturbing catch is a **GDB hardware watchpoint** on the victim dentry's
  refcount word; code audit (round2.md + this round) hasn't pinned the over-drop.

## NEXT (round 3) — catch the over-drop without perturbing layout
1. **GDB watchpoint (non-perturbing):** boot to the fault ONCE, note the aborting
   dentry ptr (rdx); reboot (deterministic), `watch *(rdx+8)` early, continue — the
   trap names the code doing the extra decrement. (Only method that doesn't move it.)
2. **Audit dentry get/put balance** in `clone_tree.rs` (clone_mnt/copy_tree/commit_tree/
   release_clone), `detach.rs`, `reap_ns` — a shared dentry dropped once more than
   grabbed (a Weak-vs-strong slip, a temporary double-dropped, or a skipped-clone
   release that puts a dentry the commit never got). get/put_mountpoint via
   `mnt_mp.take()` is double-put-safe (leaks, not underflows) — so the imbalance is a
   raw Arc<Dentry> drop, not the mountpoint m_count.

## round2.md (parallel investigation) — earlier lead (ns-id now DISPROVEN above)
`round2.md` (repo root, read-only pass) independently confirms: external heap
corruption of a NAMESPACES BTreeMap edge → 0x60 (≈ ns-id 96 ≈ live ns count).
Its strongest code lead — the **mount-namespace lifecycle is SPLIT into two
models** (a real broken system, fix candidate):
- `mntns.rs` declares the canonical registry + `alloc_ns_id()` + `mnt_ns_enter/exit`
  pin/reap — but `mnt_ns_enter/exit` are DEAD outside tests.
- Production ns transitions bypass it with raw-id `AtomicU64::store`:
  `syscalls/src/272_unshare.rs` has its OWN `static NEXT_MOUNT_NS` (not
  `alloc_ns_id`), `apply_new_namespaces()` does `task.mount_ns.store(new_id)` with
  no enter/exit; `056_clone.rs` copies `child.mount_ns.store(...)`; `nscg/proc_ns.rs`
  setns does `cur.mount_ns.store(ns.id)`; `sys_exit`/`terminate_current_with_signal`
  never `mnt_ns_exit`. → no coherent live-object graph under sandbox churn; a ns
  object may be reaped/freed while still referenced (→ UAF → the wild-write), or
  the two id spaces (NEXT_MOUNT_NS vs NEXT_NS_ID) diverge.
- `Task::mount_ns` is NOT at offset 0x60, so it's not a trivial task-field clobber.
round2.md's explicit rule: **"No guess-fix should land here — catch the first
mutation of the bad node, not patch around the crash."** (matches no-hacks.)

## NEXT — catch the wild-writer (do NOT guess-fix heap corruption = a hack)
0. **Redzone attempt MASKS it:** the uncommitted redzone helpers in
   `kalloc/src/poison.rs` (parallel agent) + wiring them caused a 35s stall
   (32B/alloc layout shift + per-free check overhead moves the victim earlier) —
   confirms heap-layout-sensitivity but doesn't reach the 53s overflow. Prefer
   round2.md's LESS-disruptive probes below.
1. **NAMESPACES integrity check** around each ns transition (round2.md): before/
   after `devfs::snapshot_ns`, `vfs::mount::snapshot_ns`, `task.mount_ns.store`,
   `setns_apply` — walk NAMESPACES asserting node ptrs are canonical; first trip
   narrows the corruptor to that op. + log every raw ns transition (tid/old/new).
1. **GDB hardware watchpoint**: boot paused, break at `resolve_mount`, at ~53s read
   `NAMESPACES` root-node addr (`vfs::mntns::NAMESPACES`), set a `watch` on its edges
   region (offset 0xc0..), continue — the trap names the writer.
2. **OR integrity check**: add a debug fn that walks NAMESPACES asserting every node
   ptr is canonical-kernel (>= 0xffff_8000_..); call it from the watchdog tick; when
   it trips, dump recent mount/ns ops → narrows WHEN + which op corrupts it.
3. Suspect the ns-churn path (clone/unshare CLONE_NEWNS + reap): `mntns.rs`
   ns_get_or_create/ns_forget, `mount/clone_tree.rs`, `mount/namespace.rs`. Look for a
   place a u64 ns/mnt id lands in a pointer field, or a BTreeMap node UAF under churn.
   Related: [[mount-dentry-sharing-gotcha]].

## First commands next session
1. `cd /home/nd/oxide/kernel && git log --oneline -4`  # main @ addb3341+ (B708/D200 merged)
2. Boot: `qemu_start arch=x86_64 features=debug-boot smp=2 mem=4G rebuild_rootfs=true`
   → run_until 'FAULT|resolve_mount' (fires ~53s, deterministic).
3. addr2line the fault rip; the loop = NAMESPACES BTreeMap walk; hunt the 0x60 writer.

## Gotchas
- run_until/qemu_serial buffers cap ~58KB (token limit); parse saved tool-result files
  with python; check `[FAULT]`/`[CPU-STALL]` at the true tail (visible tail lags guest).
- Boots ~flaky but this fault is DETERMINISTIC (2/2). ext4: hosted e2fsck gate, no boots.
- Clean image: `../images/out/gnome-x86_64-root.img`. again.ms (root-authored) diagnosed
  the epoll+mmio blockers — both now fixed + merged.
