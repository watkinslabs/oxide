# bootswap — self-bootstrap (GRUB/Multiboot2) handoff analysis

Working analysis for replacing Limine with our own boot path. Goal:
GRUB loads the kernel ELF directly via Multiboot2; our 32→64-bit
trampoline sets up long mode + page tables and hands the kernel the
same uniform `BootInfo` Limine produced. Status: GRUB boots through
CPU/MMU/HHDM/PMM/device-map/LAPIC; remaining work is making the
trampoline's handoff satisfy every **implicit** contract the kernel
inherited from Limine.

Branch `F372-grub-multiboot2`. Verify via `make smoke-grub`
(`SMOKE_KEEP_LOG=<path>` keeps the serial log; `OXIDE_QEMU_KVM=1` for
fast boots; `OXIDE_QEMU_DINT=<file>` adds `-d int` exception tracing).

**Current status: GRUB boots to `oxide login:`** (make smoke-grub PASS,
34s under KVM). Full chain works: long-mode trampoline → kernel init →
PCI enum → virtio-net eth0 → systemd → Console Getty → login prompt.
GRUB now boots the identical kernel+userspace as Limine, replacing it.
All six handoff bugs below are resolved.

The earlier "ctxsw rotation hang" was a **red herring of the boot
flavor**: `cmd_grub` forced `--features debug-all`, which runs the
`debug_sched!` bring-up smokes (`smoke_rr` etc.). Those `sti; hlt` in
`tick_yield` on a timer the device-map smoke deliberately disarmed →
deadlock. That is a debug-all property (would hang under Limine+debug-
all too), not a GRUB issue. The real login path (`make qemu-x86`) uses
`debug-boot`; `cmd_grub` now matches it. Run those smokes explicitly
with `make qemu-x86-grub FEATURES=...`/`--features debug-all` if needed.

## Boot chain

```
GRUB 2.12 (BIOS El Torito ISO)
  → reads .multiboot2_header (entry-address tag, type 3) in first 32 KiB
  → loads PT_LOADs by physical addr (p_paddr) — must be < 4 GiB
  → jumps 32-bit protected mode → _mb2_entry (physical ~0x201000)
_mb2_entry  [.code32]   crates/arch/boot-x86_64/src/mb2.rs
  → save EAX(magic)/EBX(mb2 info ptr) → "MB2"
  → build boot page tables → enable PAE+EFER(LME|NXE)+CR0.PG
  → lgdt temp 64-bit GDT → ljmp $0x08 (compat→64-bit, identity phys)
_mb2_long   [.code64]
  → load data segs → movabs+jmp to higher-half VMA
_mb2_high   [higher-half]
  → (tear down low identity) → "L64" → jmp _start
_start  (bootloader-agnostic)  crates/arch/boot-x86_64/src/lib.rs
  → mov rsp,KERNEL_STACK → _start_rust
_start_rust
  → UART/klog → GDT → TSS → IDT → PIC mask → syscall MSRs → SSE
  → TSC calibrate → capture_cmdline → build_boot_info → kernel_main
```

## Linker (`link/x86_64-kernel.ld`)

- VMA base `KERNEL_BASE = 0xFFFFFFFF80000000` (higher-half).
- `KERNEL_PHYS = 0x200000`; every PT_LOAD gets `AT(ADDR(sec) -
  KERNEL_BASE + KERNEL_PHYS)` so its LMA (p_paddr) is low (< 4 GiB).
  GRUB loads by p_paddr → without this, "segment crosses 4 GiB border".
- Limine ignores p_paddr (maps by p_vaddr) so the AT() is invisible to
  the Limine path. A kernel symbol's physical address = `sym -
  KERNEL_BASE + KERNEL_PHYS`.

## Trampoline page tables (current)

2 MiB pages, all arch-baseline (no PDPE1GB needed):

| PML4 slot | VA base | target |
|---|---|---|
| `[0]` | `0` | pdpt_low → pd_low: identity 0..1 GiB |
| `[256]` | `0xffff800000000000` | pdpt_hhdm → pd_low: HHDM, identity 0..1 GiB |
| `[511]` | `0xffffffff80000000` | pdpt_high → pd_high: VMA→phys KP (kernel image) |

- pd_high entry[i] = `(i+1)*2 MiB` so VMA base maps to phys `KP`
  (2 MiB) — the kernel's LMA, NOT phys 0. **This +KP offset is the
  crux**: GRUB loaded us at `KP`, so higher-half VMA must map to LMA.
- Identity (`[0]`) only needed transiently: the 32-bit trampoline keeps
  executing at its ~2 MiB physical address across the CR0.PG flip,
  until the far/`movabs` jump reaches the higher-half VMA.

## The implicit Limine→kernel contract

The kernel was written against Limine's handoff. These are the
assumptions the trampoline must reproduce (each was a separate bug
when missing):

1. **EFER.NXE = 1.** The kernel's device/user/rodata page leaves set
   the NX bit (63). With NXE off, NX is a *reserved* bit → first
   access to any NX page faults `#PF` err bit3 (RSVD). Symptom: HPET
   device read faulted at `0xffffff00fed00000`, err=0x08. Limine sets
   NXE. → trampoline sets EFER bits 8 (LME) **and** 11 (NXE). **DONE.**

2. **Legacy 8259 PIC masked / remapped.** Default PIC maps IRQ0 (PIT)
   to vector 0x08 = the `#DF` exception slot. A live PIC + free-running
   PIT vectors a timer tick into the double-fault handler at the first
   `sti`. Limine masks the PIC; GRUB does not. Symptom: `#DF` storm
   ("Servicing hardware INT=0x08") during the LAPIC periodic-timer STI
   window. → `remap_and_mask_pic()` in `_start_rust` (ICW1-4 remap to
   0x20-0x2F + mask all). Bootloader-agnostic; harmless under Limine.
   **DONE.**

3. **No low identity map in the kernel-active tables.** `user_map::run`
   (kernel_main:408, *before* `user_as::init`:475) maps `0x400000` on
   the **master/active** tables via global `MmuOps::map`; its comment
   expects to allocate `PML4[0]/PDPT[0]/PD[2]/PT[0]` — i.e. `PML4[0]`
   empty. Our 2 MiB identity *block* at `PML4[0]` → `walk_or_alloc`
   hits a block → `WalkErr::HitHugeOrBlock` → `MmuOps::map walker
   failure` panic at `va=0x400000`.
   - Limine leaves no low identity block the kernel maps over.
   - → `_mb2_high` clears `PML4[0]` (entry = 0) after reaching
     higher-half. Walkers read the entry from memory (= 0) and allocate
     fresh; per-VA `map()` calls `flush_va`. **DONE** — but only works
     together with #7 (boot stack). **`docs/20:20` "identity map
     preserved for early access" turned out NOT to be a real
     requirement** — nothing the kernel does early needs it once #4
     (RSDP via HHDM) and #7 (boot stack) are fixed. Verified:
     `user-map-smoke: ok pa=0x3ffd8000`.

4. **RSDP is reported as a dereferenceable kernel VA, not a raw
   physical.** `firmware::acpi::parse_and_log_rsdp(rsdp_va)` does
   `let p = rsdp_va as *const u8` and dereferences directly
   (`acpi.rs:182`). kernel_main passes `info.rsdp_pa`; its own comment
   (`lib.rs:216`) says "the Limine-supplied kernel **VA** for the RSDP
   (HHDM-mapped)". So despite the `_pa` name and limine-proto calling
   `.address` "physical", the value the kernel consumes is an **HHDM
   virtual address**. XSDT/MADT/HPET decoders correctly use
   `hhdm + pa`; only the RSDP arg is pre-offset.
   - Our MB2 `build_memmap` set `rsdp_pa = (tag+8) - MB2_HHDM` (raw
     physical). The kernel deref'd a low VA → fault once identity was
     gone (`cr2=0x15cef0`, NP-R-K, in `try_log_acpi`).
   - → report `rsdp = MB2_HHDM + phys` (HHDM VA), matching Limine. Then
     ACPI works **without** any identity map. **PENDING.**

5. **CR3 self-reload is unnecessary and wedges boot.** Reloading CR3
   (`mov cr3,rax; mov rax,cr3`) to flush the TLB after clearing the
   identity entry hung boot right after "L64" under both TCG and KVM
   (cause not fully diagnosed). It is not needed: walkers read PT
   entries from memory via HHDM, and `map_at_level` flushes each
   mapped VA itself. → clear `PML4[0]` with no CR3 reload. **DONE
   (in the pending #3 patch).**

6. **HHDM must cover the physical ranges the kernel touches early.**
   Currently 1 GiB. ACPI tables sit near the top of 1 GiB RAM
   (`xsdt≈0x3ffe231f`) — covered, but only by ~245 KiB of slack.
   Limine maps a larger HHDM (typically ≥ 4 GiB). → extend HHDM to
   4 GiB (4 × 2 MiB-page PDs) for headroom and to match Limine; device
   MMIO (0xfed00000) then also reachable via HHDM as a bonus (the
   device-map window at `KERNEL_DEVICE_BASE = 0xffffff00_00000000`
   stays the primary MMIO path). **PENDING (robustness).**

7. **The trampoline must hand `_start` a valid stack.** GRUB leaves
   `rsp` pointing at its own low-memory stack and does not set one up
   for us; Limine hands off with a valid stack. `_start`'s Rust
   prologue pushes before its inline-asm `mov rsp` runs, so with the
   low identity map gone (#3) that first push faulted on GRUB's now-
   unmapped low `rsp` → no IDT yet → triple fault → `-no-reboot` halt
   (looked like a hang with no breadcrumb). **This, not any identity
   dependency, was the real cause of the "needs identity" early hang.**
   → `_mb2_high` sets `rsp = mb2_boot_stack_top` (a 16 KiB higher-half
   .bss stack) before `jmp _start`; `_start` then swaps to
   `KERNEL_STACK`. **DONE.** Diagnosed via raw COM1 breadcrumb bytes in
   `_start_rust` (none printed → fault before the first one → in
   `_start`/prologue, not a later init step).

## Kernel paging model (consumers of the handoff)

- `mm-pmm/setup.rs::init_from_boot_info`: walks memmap, uses only
  `BootMemKind::Usable` regions; relies on the memmap carving out the
  kernel image. Limine emits a `KernelImage` region; GRUB's raw e820
  marks that RAM `Usable`. → MB2 `build_memmap` splits each available
  region around `[KP, __kernel_end_phys)` and emits the middle as
  `KernelImage`. **DONE** (verified: log shows `KERNEL base=0x200000
  len=0xc239000`, PMM reports 829 MiB free, stress balanced).
- `hal-x86_64::mmu_ops`: `HHDM_OFFSET` set once from
  `BootInfo.hhdm_offset`; every PT walk uses `hhdm + table_pa`. Active
  CR3 is our trampoline PML4 until `user_as::init`.
- `user_as::init` → `capture_kernel_master` (CR3) + `new_user_pml4`
  (alloc fresh PML4, zero, copy entries `[256..512]` from active CR3 —
  shared kernel half) → `activate` (CR3 := user root). Kernel-half
  PML4 entries are shared by pointer, so kernel mappings added after
  the clone propagate; user half is private/empty per AS.
- `smoke/elf.rs::run_as_task`: builds an ELF, creates a per-task AS via
  `new_user_pml4`+`AddressSpace::new`+`activate`, maps the blob at
  `0x400000` in that AS (empty low half — no identity conflict). The
  *earlier* `0x400000` failure is the `user_map` smoke mapping on the
  master tables, which #3 fixes.

## BootInfo we produce (MB2 path) vs Limine

| field | Limine path | MB2 path (current) | correct? |
|---|---|---|---|
| memmap | `populate_memmap_into` | carved e820 + KernelImage | ✓ |
| hhdm_offset | Limine HHDM resp | `MB2_HHDM = 0xffff800000000000` | ✓ |
| rsdp_pa | Limine resp (**HHDM VA**) | raw physical | ✗ → HHDM VA |
| boot_ns | timer | timer | ✓ |
| seed | 0 (TODO) | 0 | ✓ (parity) |
| smp_* | Limine SMP resp | 0 (UP) | ✓ for now |
| cmdline | EXECUTABLE_FILE | MB2 tag type 1 | ✓ |

## Remaining plan (in order)

1. ~~RSDP as HHDM VA~~ **DONE.**
2. ~~Identity teardown + boot stack~~ **DONE** (#3 + #7).
3. ~~ctxsw rotation hang~~ **NOT A BUG** — debug-all smoke deadlock;
   `cmd_grub` now defaults to `debug-boot` (the login path).
4. ~~`make smoke-grub` to login~~ **DONE** (x86 KVM PASS, 34s).
5. **Serial RX gap (OPEN — next task).** GRUB boots to the `oxide
   login:` prompt and systemd runs (Console Getty started), but typed
   serial input does NOT reach the getty: `boot-smoke-login grub` sends
   `alice\n` and nothing echoes / no PAM start, while the identical
   `boot-smoke-login x86` (Limine) PASSes (alice→PAM→shell→uid=1000 in
   37s). So serial **output** works on the GRUB path but serial
   **input** (RX) does not. Ruled out: the qemu serial chardev (now
   identical `stdio,id=ser0,signal=off` to the Limine headless path)
   and the kernel cmdline (`console=ttyS0,115200` identical; GRUB now
   also passes `BOOT_IMAGE=`/`quiet`). Likely the COM1 RX IRQ (IRQ4)
   routing through the IOAPIC, or serial-driver RX init state left by
   GRUB's `terminal_input serial`. **A printed prompt is NOT a working
   login — do not claim GRUB login works until RX is fixed and
   `boot-smoke-login grub` PASSes.** Next: trace the serial-tty RX path
   + IOAPIC redirection entry for IRQ4 under the GRUB boot vs Limine.
6. Extend trampoline HHDM to 4 GiB (4 PDs) — robustness.
7. ARM lockstep: verify `make qemu-arm` still reaches login (Limine
   path; PIC mask is x86-only, no ABI change) — no regression.
8. Multiple GRUB menu entries / boot options; then drop Limine.

## Latent bug noted (not GRUB-related)

`debug-all` boot deadlocks: `smoke_rr`/`smoke_preempt` run after the
device-map smoke disarms the LAPIC periodic timer, but `tick_yield`'s
`sti; hlt` needs a timer tick to wake. Under debug-all the RR rotation
wedges. Pre-existing (bootloader-independent); worth a separate fix
(re-arm a periodic tick for the duration of the sched smokes, or make
`tick_yield` not halt when other tasks are runnable).

## Open questions

- Why the CR3 self-reload wedges post-L64 (worked around, not root-
  caused). Low priority — the reload is not needed.
- Whether to keep a low identity map at all long-term, or commit fully
  to HHDM-only physical access (matches the kernel's actual rsdp
  contract). Current decision: no low identity map after handoff.
- Does any *other* early kernel path deref a raw physical as a VA?
  Audited `firmware/acpi.rs`: only the RSDP arg (line 182); XSDT/MADT/
  HPET/MCFG/GTDT all use `hhdm + pa`. No others found.
