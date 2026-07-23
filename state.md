## Handoff: kalloc corruption hunt — DECODED corrupted bytes, points at zram sysfs write path

### Headline
Long-running hunt for a memory-corruption bug that crashes every boot around the
`[ZRAM-SYSFS] disksize=...` event (bare `debug-boot` smoke, ~15-25s repro, recipe
below). This session's biggest break: **a corrupted `HoleHdr.size` field decoded
to readable ASCII** — `0x646c6f6873657268` as little-endian bytes is literally
`"hreshold"`, part of the word **"threshold"**. That string, as a match-arm
literal, exists in exactly one place in the whole tree:
`crates/drivers/drv-zram/src/writeback/recompress.rs:28` (`"threshold" =>
threshold = value.parse::<usize>()...`), parsing the zram `recompress` sysfs
attribute. **Root cause still open** (the parsing code itself is safe Rust, no
unsafe/raw buffer — the actual bug is upstream of it, not yet found) — this is
a concrete, specific, evidence-backed lead, the strongest of the whole hunt.
Also fixed 2 more real UAFs this session (B1334, B1335) via a 6-agent sweep;
neither confirmed as root cause. 9 more real bugs from earlier this session,
also not the root cause (list at bottom).

### THE DECODED-STRING LEAD (new, most promising)
Sample (`smp=1`, `debug-boot,debug-dealloc-diag`, ~21s, at the usual
`[ZRAM-SYSFS] disksize=...` trigger):
```
[KALLOC] free-list-node-overflow addr=ffffffff8182fd38 size=646c6f6873657268
[KALLOC] dealloc-failed tag=address-overflow ptr=ffffffff8182f6a0 size=18 align=1
[PANIC] crates/shared/kalloc/src/lib.rs:807: kalloc invalid free
```
`size=646c6f6873657268` interpreted as a little-endian `u64`'s bytes
(`python3 -c "print((0x646c6f6873657268).to_bytes(8,'little'))"`) is
`b'hreshold'` — literal ASCII, not numeric garbage. This is DIRECT PROOF the
corrupting write copies real text/string data into freed heap memory — not a
generic "zero" or a stray pointer value like every prior sample this hunt found.
Traced the string upstream, all clean/safe so far:
1. `drv-zram/src/writeback/recompress.rs:28` — the `"threshold"` match arm
   itself. Pure safe Rust (`&str` matching, no raw pointers). Not the bug.
2. `drv-zram/src/state.rs:338-340` (`Zram::recompress_text`) — thin wrapper,
   calls into (1). Safe.
3. `crates/kernel/sysfs/src/block/zram.rs:132-140` (`store()`) — `buf: &[u8]`
   → `core::str::from_utf8(buf).trim()` → dispatch to `recompress_text`. Safe.
4. `crates/kernel/sysfs/src/kobject.rs:85-88` (`write()`) — `buf: &[u8]` (from
   the VFS write syscall) → `d.ops.store(d.name, buf)`. Safe, no fixed-size
   buffer visible.

**TRACED ONE MORE HOP this session, changes the theory:** `sys_write`
(`crates/kernel/syscalls/src/001_write.rs:113-126`) does NOT copy the write
buffer into kernel memory at all — it validates the user range
(`userbuf::validate_user_buf_readable`) then builds a **zero-copy slice
directly into the CALLER'S user-space memory**:
`unsafe { core::slice::from_raw_parts(buf as *const u8, cnt) }`. So the literal
bytes `"threshold"` reaching `zram.rs`'s `store()` never exist in a
`kalloc`-owned kernel buffer at that point — no fixed-size kernel copy to
overflow here. This REVERSES the earlier "too-early free of a per-write scratch
buffer" theory (there is no such kernel buffer in this path) and makes the
**klog ring-buffer theory (see "Alternative explanation" below) now the leading
one**: something IN THE ZRAM CODE PATH logs a message containing "threshold"
(candidates: `trace_store`'s `debug-zram` tracer at `sysfs/src/block/zram.rs:
124-128`, which does `klog::write_raw(value.as_bytes())` — if `debug-zram` was
compiled in for a sample where this was captured, that copies "threshold" bytes
into klog's ring buffer, a static/global buffer, NOT a `kalloc` allocation
either — so if the ring buffer itself isn't `kalloc`-backed, this doesn't
explain it either. Checked every `format!`/`String::from`/`.to_string()` call in
`recompress.rs`/`state.rs`(zram)/`sysfs/block/zram.rs`/`kobject.rs` — none of
them format or copy the literal word "threshold" (the `format!` calls there are
all numeric/path values for the READ side of other attributes, e.g.
`"disksize" => format!("{}\n", st.disksize)`). **No owned-string construction of
"threshold" found anywhere in the traced files.** The only places the literal
byte sequence `"threshold"` exists at all are: (a) the kernel binary's `.rodata`
match-arm string constant (read-only, never `kalloc`-backed, can't be "freed"),
and (b) transiently in whatever USER-SPACE buffer a userspace tool wrote
(zero-copy per `sys_write`, never enters `kalloc` either). **This is now a real
puzzle**: none of the 3 places bytes containing "threshold" plausibly exist
(.rodata, user memory, klog's static ring buffer — also ruled out, see above)
are `kalloc`-allocated, yet the corrupted `HoleHdr` — which IS `kalloc` memory —
contains those bytes. Possibilities for next session: (a) broaden the grep
beyond the 4 files traced so far — search the WHOLE `drv-zram` crate and its
callers for any `format!`/owned-`String` that could embed "threshold" as a
*substring* of a longer message (not just the bare word), or (b) reconsider
whether the address really is heap memory — `nm`'s nearest-symbol resolution
only proves the address is AFTER `kalloc::STATIC_HEAP`'s start, not that it's
strictly before its end; re-verify the corrupted address is actually within the
live heap's registered region bounds, not accidentally past it into adjacent
kernel-image data.

**Broadened the grep to the whole `drv-zram` crate**: every OTHER occurrence of
the literal string "threshold" is in `#[cfg(test)]`-gated test files
(`tests.rs`/`tests/foundation.rs`) — NOT compiled into the real kernel binary
that boots. The only runtime occurrence is the `.rodata` match-arm constant
itself. **This shifts the leading theory: the source is very likely a REGISTER
or STACK value, not a heap/static buffer.** While a task executes
`recompress_text`'s `match name { "threshold" => ... }` (a byte-compare that
loads the constant's bytes into a register), an interrupt/context-switch that
mishandles that register — the SAME general hazard class as B1333's
`oxide_context_switch` register-clobber bug, just a DIFFERENT, not-yet-found
instance — could write its leftover value to an unrelated heap address. Next
session: reframes "trace the string's copy path" (dead end, no such copy
exists) into "find what runs on a timer tick / IRQ / context switch shortly
after `recompress_text`'s match executes, and whether ANY of those paths writes
a caller-saved-but-not-actually-saved register to memory" — much closer to
B1333's fix shape than a buffer-lifetime bug.

**Second alternative, still open**: a kalloc-internal logic gap where a node
gets linked into the free list without `new_ptr.write(HoleHdr{...})` actually
running for it, leaving whatever stale content was already there (not
necessarily "threshold"-related at all). Check `try_merge` with this in mind:
does any merge path link a node into the chain without writing/updating its
header fields at the merge boundary?

### Diagnostic gap found this session (separate, minor): alloc-path tags silent
Two more `kalloc front/back fragment invalid` panics this session (in `alloc()`,
not `dealloc()`) printed **zero** `[KALLOC]` diagnostic tags despite the exact
same `add_free_region`/`try_merge` code (now fully tagged, confirmed present in
the binary via `strings`) being on the failing path. `dealloc()`-triggered
failures DO print tags reliably (see the sample above). Suspect: `alloc()`'s
fragment-reinsertion calls happen while IRQs are disabled
(`self.irq_off()`), and `klog::write_primary_raw`'s underlying console sink may
be interrupt-buffered rather than fully synchronous/polled — if so, bytes
written right before a panic (which halts before IRQs restore) never actually
reach the UART. Not yet confirmed; worth checking `klog::console::primary_only`
and the UART driver's TX path for polled-vs-buffered behavor if this recurs.

### B1334 + B1335: two more real UAFs found via systematic sweep (merged)
6-agent sweep of all 16 kernel files containing `Arc::into_raw`/`from_raw`; 14
clean, 2 real bugs fixed:
- **B1334** (`mm-vmm/rmap.rs`, `PageRmap::anon_vma()`): raw-pointer TOCTOU on an
  `Arc` refcount, no lock. Fixed with a proper `Spinlock`. **Zero callers in the
  tree — dead code**, unlikely to be root cause.
- **B1335** (`process_vm_readv`/`writev`): foreign task's `Arc<AddressSpace>`
  was dropped before the chunked copy loop that uses its physical address —
  `process_vm_writev` could write into freed-and-reallocated physical memory if
  the target exits mid-transfer. Fixed by holding the `Arc` for the whole loop.
  **Live, reachable syscall path** — plausible candidate, unconfirmed.

### Heap-growth crash (traced, ruled out as a NEW bug)
A `growth-register-failed tag=outside-owned-region` sample earlier this session
was hand-traced through `HoleList::add_region` and `pmm::boot::kalloc_grow` —
both self-consistent, no bug in either. Very likely another discovery of the
same still-unidentified corruptor, not a distinct growth-path bug. Don't
re-derive this math again without new evidence.

### dcache (traced, ruled out as source, still a frequent victim)
3 of 9 pre-this-pass crash samples hit dcache/`Dentry` code. Read `hash.rs` +
`lifecycle.rs` end-to-end — both correctly locked/ordered. dcache is high-churn
so it's the most frequent victim by chance, not the source. Don't re-narrow here
without new evidence.

### Non-determinism (established, don't re-litigate)
12+ distinct crash shapes seen this session across ~18 boots. Never attribute a
fix from fewer than 3-5 boots.

### Fast-repro recipe
```
mcp__qemu__qemu_start(arch=x86_64, features="debug-boot,debug-dealloc-diag", smp=1)
mcp__qemu__qemu_continue(...)   # times out at 120s internally, boot continues regardless
# wait ~25-35s, then qemu_serial() and grep for FAULT/PANIC/KALLOC/TASK-STACK-GUARD
```
When a `[KALLOC]` tag shows a `size=` or address value, **always try decoding it
as little-endian ASCII bytes first** (`python3 -c "print((0x...).to_bytes(8,
'little'))"`) — this session's biggest lead came from exactly that, and no
earlier session tried it. `debug-heappoison` = same repro but ~500s — **user has
explicitly vetoed this for iteration**, one boot only if truly needed. Always
`qemu_list`/`qemu_stop` stale instances first.

### Concrete next steps (priority order)
1. **Trace the sysfs-attribute `write()` syscall path** (find `sys_write`'s VFS
   dispatch into `File::write`, then how the user buffer becomes `buf: &[u8]`
   for `kobject.rs`'s `write()`) for a fixed-size buffer, an off-by-one, or a
   too-early free — see "THE DECODED-STRING LEAD" above. This is the single
   most promising unexplored thread.
2. Rule in/out the "merge links a node without writing its header" alternative
   in `try_merge` (`holes.rs`) — re-read with fresh eyes for this specific
   possibility.
3. Get 3-5 more boot samples on current `main`, decode every corrupted
   `size`/address as ASCII, and see if more decode to readable text — that
   would strongly confirm the "stale/freed buffer content" theory generally,
   not just for zram.
4. Audit `ContextAArch64::switch` (`crates/arch/hal-aarch64/`) for B1333's
   register-clobber hazard — still not checked, needed for ARM/x86 lockstep.

### Housekeeping (all merged, don't re-investigate; SHAs/details in git log)
9 real cross-CPU UAF/logic bugs from earlier this session (Task field races,
ext4 UAF, corruption-probe fixes) — none the root cause. B1332 hw-watchpoint +
`[TASK-DROP]` diagnostics (exhausted, kept). B1333 ctxsw register-clobber fix.
C156-C163: kalloc diagnostic-tag gaps + `size_track.rs` (kept, never fired).
B1334/B1335 (this pass): rmap TOCTOU (dead code) + process_vm foreign-AS UAF
(live path). Neither B1334 nor B1335 confirmed/denied as root cause yet.

First command next session: `grep -rn "fn sys_write" crates/kernel/syscalls/src/`
then trace into VFS `File::write` → `kobject.rs`'s `write()` for the sysfs
attribute buffer's exact allocation/lifetime — see "Concrete next steps" #1.
