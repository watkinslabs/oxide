# Manifest

Authoritative index of every spec. Per `02§6`. Status changes update both file and this index in same commit.

## Charters

| File | Status | Frozen | Depends |
|---|---|---|---|
| `00-master-plan.md` | DRAFT | — | — |
| `01-glossary-and-types.md` | FROZEN | 2026-05-02 | `02`,`08`,`09` |
| `02-spec-discipline.md` | FROZEN | 2026-05-02 | — |
| `03-modernity.md` | DRAFT | — | — |
| `04-performance.md` | DRAFT | — | `02` |
| `05-pre-mortem.md` | DRAFT | — | `00`,`03`,`04` |
| `06-memory-model.md` | FROZEN | 2026-05-02 | `01`,`02`,`08`,`09` |
| `07-toolchain-and-targets.md` | FROZEN | 2026-05-02 | `02`,`08` |
| `08-ai-density.md` | FROZEN | 2026-05-02 | `02` |
| `09-abbreviations.md` | FROZEN | 2026-05-02 | `08` |

## Subsystems

| File | Status | Frozen | Depends |
|---|---|---|---|
| `10-pmm.md` | DRAFT | — | `01`,`02`,`06`,`04` |
| `11-vmm.md` | DRAFT | — | `01`,`02`,`06`,`10`,`14`,`20`,`21` |
| `12-slab.md` | DRAFT | — | `01`,`02`,`06`,`10` |
| `13-sched.md` | DRAFT | — | `01`,`02`,`06`,`14` |
| `14-context-switch.md` | DRAFT | — | `01`,`02`,`06`,`07` |
| `15-syscall-abi.md` | DRAFT | — | `01`,`03`,`06` |
| `16-vfs.md` | DRAFT | — | `01`,`02`,`06`,`12`,`15` |
| `17-block-and-pagecache.md` | DRAFT | — | `01`,`02`,`06`,`10`,`11`,`12`,`16` |
| `18-modules.md` | DRAFT | — | `01`,`02`,`06`,`08`,`09`,`11`,`15`,`27`,`31` |
| `19-dev-proc-sysfs.md` | DRAFT | — | `01`,`02`,`06`,`16`,`18`,`35` |
| `20-hal-x86_64.md` | DRAFT | — | `01`,`02`,`06`,`07`,`14`,`22`,`23`,`38` |
| `21-hal-aarch64.md` | DRAFT | — | `01`,`02`,`06`,`07`,`14`,`22`,`23`,`38` |
| `22-irq-and-exceptions.md` | DRAFT | — | `01`,`02`,`06`,`07`,`14`,`20`,`21` |
| `23-time.md` | DRAFT | — | `01`,`02`,`06`,`07`,`14`,`20`,`21`,`22` |
| `24-ipc.md` | DRAFT | — | `01`,`02`,`06`,`12`,`13`,`16`,`23` |
| `25-net.md` | DRAFT | — | `01`,`02`,`06`,`12`,`13`,`16`,`24`,`33`,`34` |
| `26-namespaces-cgroups.md` | DRAFT | — | `01`,`02`,`06`,`13`,`16`,`19`,`25`,`27` |
| `27-security.md` | DRAFT | — | `01`,`02`,`06`,`11`,`13`,`16`,`18`,`26`,`38` |
| `28-tty-pty.md` | DRAFT | — | `01`,`02`,`06`,`16`,`19`,`24` |
| `29-init-and-userspace.md` | DRAFT | — | `01`,`02`,`13`,`15`,`16`,`19`,`28`,`31`,`39` |
| `29a-userspace-platform.md` | DRAFT | — | `02`,`03`,`07`,`15`,`29`,`31`,`39`,`43` |
| `30-io-uring.md` | DRAFT | — | `01`,`02`,`06`,`11`,`13`,`15`,`16`,`17`,`23`,`25` |
| `31-elf-loader.md` | DRAFT | — | `01`,`02`,`11`,`12`,`16`,`18`,`27` |
| `32-power-reset.md` | DRAFT | — | `01`,`02`,`15`,`20`,`21`,`33` |
| `33-firmware-tables.md` | DRAFT | — | `01`,`02`,`19`,`20`,`21`,`34` |
| `34-pci-and-pcie.md` | DRAFT | — | `01`,`02`,`11`,`19`,`22`,`33`,`35` |
| `35-drivers.md` | DRAFT | — | `01`,`02`,`16`,`18`,`19`,`22`,`34` |
| `36-bootloader-handoff.md` | DRAFT | — | `01`,`02`,`07`,`20`,`21`,`33`,`39` |
| `37-observability.md` | DRAFT | — | `01`,`02`,`04`,`13`,`19`,`23`,`38` |
| `38-error-handling.md` | DRAFT | — | `01`,`02`,`07`,`08` |
| `39-build-and-image.md` | DRAFT | — | `02`,`07`,`29`,`36` |
| `40-ci-and-soak.md` | DRAFT | — | `02`,`05`,`07`,`39`,`42` |
| `41-debug-flags-catalog.md` | DRAFT | — | `04`,`07`,`08` |
| `42-test-strategy.md` | DRAFT | — | `02`,`05`,`06`,`07`,`08`,`40` |
| `43-acceptance.md` | DRAFT | — | every spec |

## Cross-cutting

| File | Status | Frozen | Depends |
|---|---|---|---|
| `boot-flow.md` | DRAFT | — | `20`,`21`,`33`,`36`,`29` |

## Freeze order

Charter docs first (no inter-charter cycles): `02` → `08` → `09` → `01` → `06` → `07` → `04` → `03` → `38`. Then subsystem leaves: `14`,`23`,`22`,`33`,`36` (HAL/firmware leaves). Then HAL: `20`,`21`. Then mid: `10`,`12`,`11`,`13`,`15`. Then upper: `16`,`17`,`18`,`19`,`24`,`27`,`26`,`25`,`28`,`30`,`31`,`32`,`34`,`35`,`37`,`29`,`39`. Then `40`,`41`,`42`. Then `43` and `00`,`05` (kept DRAFT-as-living-docs).

Charter docs `00` and `05` deliberately stay DRAFT permanently — they are living docs (master plan and pre-mortem) that should evolve as facts change.

## Open Questions

- Tooling: `xtask doc-check` to verify this index matches filesystem and per-file `Status:` lines. Lean: implement when first spec freezes.
