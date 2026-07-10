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

## NEXT — catch the wild-writer (do NOT guess-fix heap corruption = a hack)
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
