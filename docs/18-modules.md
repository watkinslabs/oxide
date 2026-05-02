# 18 Modules

DRAFT 2026-05-02. Dep:`01`,`02`,`06`,`08`,`09`,`11`,`15`,`27`,`31`. Provides:drivers, optional FS, optional net protocols.
## 1 Purpose

Load/unload signed `.ko` ELFs at runtime. Resolve against in-kernel symbol table. Per-module W^X memory. Refcount + unload safety.

## 2 Invariants (frozen)

1. Loaded module ⇒ signature verified against built-in trust root, OR kernel started with `module.sig_enforce=0` AND tainted bit `T_UNSIGNED` set.
2. Module text pages: R+X, never W. Module data: R+W, never X.
3. Symbol resolution: every `R_*_GLOB_DAT`/`R_*_JUMP_SLOT`/`R_*_CALL` resolves to (a) exported in-kernel symbol or (b) symbol in already-loaded module of equal or earlier load order. Else load fails `ENOENT`.
4. Refcount: `delete_module` only succeeds when `refcount==0` and no async work outstanding.
5. GPL gating: symbols exported `EXPORT_SYMBOL_GPL` resolve only for modules whose `MODULE_LICENSE()` is GPL-compatible. Else load fails `EACCES` and taints kernel.
6. ABI version: module's `vermagic` matches kernel's exactly. Else `ENOEXEC`.
7. Unload safety: in-flight callbacks (timers, work items, BPF progs, irq handlers, fops) drained before `module_exit` runs.

## 3 Public ifc

```rust
sys_finit_module(fd: RawFd, params: UVA<&u8>, flags: u32) -> KR<()>
sys_delete_module(name: UVA<&u8>, flags: u32) -> KR<()>

pub fn export_symbol(name:&'static str, addr:*const(), gpl_only:bool);
pub fn module_for_addr(p:*const()) -> Option<&'static Module>;
```

## 4 Format

`.ko` = standard ELF64 relocatable. Sections we care about:

| Sec | Use |
|---|---|
| `.text` | code → R+X mapping |
| `.rodata`,`.rodata.*` | const → R |
| `.data`,`.bss` | mut → R+W |
| `.modinfo` | name=value pairs (`license`,`author`,`version`,`vermagic`,`depends`,`alias`,`firmware`,`parm`) |
| `.gnu.linkonce.this_module` | `struct module` skeleton; relocated to point at module struct |
| `.init.text`,`.init.data` | one-shot init; freed after `module_init` |
| `.exit.text`,`.exit.data` | one-shot exit |
| `.altinstructions`,`.smp_locks` | runtime patching (HAL-arch) |
| `__ksymtab`,`__ksymtab_gpl`,`__kstrtab`,`__kcrctab` | exported symbols (for chained loads) |
| `__param` | module parameters |
| `.note.module.sig` | signature trailer (PKCS#7 / RSA-PSS-SHA256 over rest of file) |

## 5 Load flow

1. `finit_module(fd)`: pull in via `pagecache` → contiguous slab.
2. Verify signature: parse trailer; compare digest of (file − trailer) against signer cert in trust root. Fail ⇒ taint+enforce check.
3. Parse ELF: validate `e_machine` matches HAL arch, `vermagic` matches.
4. Allocate per-section memory: `pmm.alloc(order_for(sz))` per section, mapped via VMM kernel-space alloc.
5. Apply relocations: walk `SHT_RELA`. For each entry: resolve symbol via {in-kernel symtab, prior modules}, write fixup.
6. Make permissions strict: `.text` R+X, others per table. TLB flush.
7. Run constructors (`.init_array`).
8. Add to `modules_list`. Publish exported symbols. Update `/proc/modules`,`/sys/module/<n>`.
9. Call `module_init`. On error, reverse 1–8.
10. Free `.init.*` sections.

## 6 Unload flow

1. `delete_module(name)`: lookup in `modules_list`. EBUSY if `refcount>0` or `MODULE_FORCE_UNLOAD` not set.
2. Mark `going`. Drain: per-cpu sync, `synchronize_rcu`, timer/work flush, irq unregister waited.
3. Call `module_exit`.
4. Run destructors.
5. Remove from sysfs/procfs.
6. Free section memory.

## 7 Symbol table

Built-in symbols: linker-generated array `__start_ksymtab .. __stop_ksymtab` of `(name_offset, addr, kind)`. Crc-checked at boot. Hashed at boot into `BTreeMap<&str, KsymEntry>` for O(log n) lookup.

Per-module exports: appended on load; removed on unload. Lookup walks built-in then modules in load order.

## 8 Concurrency

- `modules_list`: RCU-protected.
- Per-module `refcount`: atomic. Increment via `try_module_get` (fails if `going`). Decrement via `module_put`.
- Symbol lookup: RCU-read.
- Load/unload mutually exclusive on a global `modules_lock` (Spinlock, class `Modules` < `MountTable`).

## 9 Perf budget

| Op | p99 |
|---|---|
| `try_module_get` | ≤ 30 cy |
| symbol lookup hit | ≤ 200 cy |
| `finit_module` (1MB module, sig verify excluded) | ≤ 30 ms |
| sig verify (RSA-PSS-2048, 1MB module) | ≤ 8 ms |

## 10 Test contract (frozen)

- Build a synthetic module crate (`tests/mod-hello/`) producing `hello.ko`. Sign with test key.
- `finit_module(hello.ko, ...)` ⇒ Ok; module shows in `/proc/modules`,`/sys/module/hello/`.
- Lookup of exported `hello_sym` returns expected addr.
- `delete_module("hello")` ⇒ Ok; references gone.
- Negative tests: unsigned (sig_enforce=1) ⇒ ENOEXEC. Wrong vermagic ⇒ ENOEXEC. GPL-only sym from non-GPL module ⇒ EACCES + taint. Refcount>0 unload ⇒ EBUSY.
- Stress: load/unload 1000 cycles random modules; no leak (verified by slab object counters and unmapped page count == start).
- Soak (bg, not gate per `40§3`): 4h cycles, load/unload concurrent with module-using workload; zero panics.
- Coverage ≥90%.

## 11 Failure modes

- Sig fail + enforce: ENOEXEC, no taint.
- Sig fail + permissive: load proceeds, set `T_UNSIGNED` taint flag, log warn.
- Reloc to undef sym: ENOENT, full rollback.
- Init returns nonzero: rollback (1–8 reversed).
- Unload while in use: EBUSY; never partial unload.

## 12 Debug

`debug-modules`: full reloc trace, sig-verify timing, per-load symbol map dump, taint-bit-history.

## 13 Cross-spec

`27` (sig trust root, taint flags, `CAP_SYS_MODULE`), `15` (syscalls 313/176), `19` (`/proc/modules`,`/sys/module/`), `35` (drivers loaded as modules), `31` (ELF parsing shared with userspace loader).

## 14 Changelog

(none)

## 15 Open Questions

- BTF/CO-RE for kernel modules? Lean: defer to v1.x with BPF.
- Module compression (zstd `.ko.zst`)? Lean: yes; saves space, decompress in `pagecache.read` before parse.
- "Live patching" (kpatch/livepatch)? Defer to v2.
- Module parameters via sysfs writes (re-tune live)? Lean: yes for those marked `0644`; `0444` is read-only.
