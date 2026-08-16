# 52 Repo structure + ownership

DRAFT (living). Dep:`02`,`07`,`08`,`39`. Provides:repo layout contract, crate ownership boundaries, naming rules.

## 1 Purpose

Pin a durable repository structure contract so subsystem code does not
drift between `kernel/src`, ad-hoc `crates/*`, and one-off folders.

## 2 Scope

1. Path layout for kernel, crates, userspace, tools, tests, docs.
2. Ownership boundaries: what lives in `kernel` vs subsystem crates.
3. Naming rules for crates/modules/files.
4. Dependency direction rules.
5. Migration rules for moving existing code without breaking velocity.

## 3 Layer model (frozen)

1. `kernel/` is the integration crate, not the primary home of
   subsystem implementation.
2. Subsystem behavior lives in domain crates under `crates/`.
3. Arch-specific behavior lives in arch crates only.
4. Tooling code lives under `tools/` only.
5. Kernel smoke probes live under `userspace/`; the boot userspace image is composed by the sibling `../images` repo,
   never in kernel subsystem crates. This repo contains no userspace runtime code — no libc, loader, NSS, PAM,
   package manager, or service manager (`29a§2`).

## 4 Layout contract (target)

```text
oxide2/
├── kernel/                    # thin integration crate
├── crates/
│   ├── kernel/                # core subsystem crates
│   ├── drivers/               # driver crates
│   ├── arch/                  # arch + boot + kernel-bin crates
│   └── shared/                # shared no_std libraries
├── userspace/                 # kernel conformance probes + smoke binaries only
├── tools/                     # xtask, lint, build helpers
├── docs/                      # specs
├── tests/                     # integration/hosted test harnesses
└── vendor/                    # kernel-build inputs only (see vendor/README.md)
```

Current `crates/<name>` paths may remain during migration; new crates
must use grouped paths from day one.

## 5 Ownership rules (frozen)

1. `kernel/src` may contain:
   - boot/init sequencing
   - cross-crate registration/wiring
   - syscall dispatch table assembly
   - top-level panic/fault policy plumbing
2. `kernel/src` may not grow new domain implementations when an owning
   crate exists (net, procfs, tty, io_uring, fs, drivers, etc.).
3. Files named `*_glue*` are adapter-only:
   - argument translation
   - trait/interface bridging
   - registration
   Not allowed: state machines, subsystem policy, long-path business
   logic.
4. Device behavior belongs in driver/domain crates, not in ad-hoc
   `kernel/src/dev_*` files, except temporary shims tracked in §9.
5. Network-namespace identity and lifetime ownership lives in
   `crates/kernel/network-namespace`; it cannot depend on tasks, networking,
   nsfs, or syscall crates.
5a. Address-space randomization policy lives in `crates/kernel/aslr`: the entropy
   budgets, the `randomize_va_space` / `mmap_rnd_bits` cells, and the address math.
   It depends only on `crng` + `hal`. `exec`, `syscalls`, `smoke` and `procfs`
   consume it; none of them may keep a second copy of a budget, a mode, or a base
   address, and no crate may draw ASLR entropy from anything but `crng`.
6. Non-network/non-mount namespace identity and lifetime ownership lives in
   `crates/kernel/namespace-identity`; it depends only on `core` + `alloc` and
   owns canonical Cgroup/Ipc/Pid/Time/User/Uts identities, ancestry, and weak
   live indexes. Tasks, nscg, nsfs, syscall, and namespace state crates consume
   it, never vice versa.
7. Cross-family socket operation policy lives in `crates/kernel/socket`:
   retained open-file classification, send/write routing, ancillary control,
   blocking completion, SIGPIPE, and message batching. Protocol endpoint state
   remains in `net`/`netlink`; syscall crates own only ABI import and copyout.
8. USER namespace `uid_map`/`gid_map`/`setgroups` state (the canonical
   id-map engine, `docs/26§2` invariant 6, `docs/26§3.6`) lives in
   `crates/kernel/user-namespace`; it depends only on `namespace-identity`
   + `core`/`alloc` (same shape as `crates/kernel/time-namespace`) and never
   looks up a `Task` or capability bit itself — callers (procfs, credential
   translation) resolve capability/ancestry and pass plain booleans/ids in.
   `crates/kernel/nscg` re-exports it as `nscg::user_ns` (same bridge
   pattern as `nscg::time_ns`); procfs is a thin view, never a second copy.
9. Cgroup BPF direct attachments, effective inheritance, revisions, modes,
   and lifetime ownership live in `crates/kernel/cgroup`. The security crate
   owns BPF UAPI validation, verification, and execution, but consumes one
   immutable cgroup-owned effective snapshot; it cannot keep a second
   attachment registry. VFS and mknod paths are enforcement adapters, never
   policy owners.
9a. Audit record production, the backlog and lost-record accounting, the
   emission rate limit, and the NETLINK_AUDIT control surface live in
   `crates/kernel/audit`. Producers (fanotify permission verdicts, Landlock
   denials, syscall-filter decisions) supply facts and never keep a second
   queue; `netlink` is the transport and owns framing and delivery only.
   Landlock's own reporting configuration — the per-layer quiet masks and
   logging flags — lives in `crates/kernel/landlock`, which decides WHAT to
   report; `audit` decides whether it is emitted.
10. `crates/drivers/drv-simplefb` owns firmware-framebuffer validation after
    handoff, WC mapping, format conversion, and fbdev/fbcon lifetime. Boot
    parsers only populate `BootInfo.framebuffer`; `kmain` only sequences the
    post-PCI fallback platform-device registration.
10a. On-disk filesystems for media formatted elsewhere live one crate per
   FORMAT, never one per mount type: `crates/kernel/fatfs` serves both `vfat` and
   `msdos`, `crates/kernel/exfatfs` serves `exfat`, `crates/kernel/ntfs3` serves
   `ntfs3` (`62§1`). Each is layered pure-decision / `Volume` / `mount`; only
   its `mount` module reaches the block layer. A mechanism two of them genuinely
   share has ONE owner, never a copy each: `crates/kernel/sectors` owns the
   volume-sector adapter over a block device and its read-modify-write rule, and
   `crates/shared/dostime` owns the 1980-epoch date/time word pair that FAT and
   exFAT both store. Registration is `syscalls::fsmount_common::registry` only.
11. `crates/kernel/sound` owns the user-visible ALSA and OSS surface for every
    sound card: card numbering and node publication, the PCM substream state
    machine and its ioctl ABI, the control-element registry and its event
    queue, and the sample-format and rate arithmetic every card shares. It
    owns no transport. A card driver supplies its identity, its capability
    masks in ALSA terms, its transfer limits and its control elements through
    `sound::ops` and `sound::elem`; a transport-private encoding (virtio's
    format enum, HD-Audio's stream format word) stays in the driver crate that
    owns that transport and is translated at the boundary.
12. `crates/drivers/drv-hda` owns HD-Audio: the controller register file,
    CORB/RIRB transport, codec enumeration, the generic parser that turns a
    widget graph into a routing plan, stream DMA, and the mixer and jack
    controls built from that plan (`61`). It is the only routing policy for an
    HD-Audio codec; there is no second table deciding what a jack is for.

13. Device-class ownership: `crates/kernel/power-supply` owns the power-supply
    class (registered supplies, the property/unit contract, per-supply
    attribute visibility, the change fan-out) and `crates/kernel/backlight`
    owns the backlight class (registered devices, brightness range and blank
    rules, the attribute contract). Both depend only on `vfs` for the errno
    type, `sync`, and `kstrtox`. `crates/kernel/sysfs` projects them and owns
    no class state; providers register into them and may not keep a second
    device list. `crates/kernel/firmware` owns the ACPI providers for both
    (control-method battery, AC adapter, video backlight) because it owns the
    AML namespace: no other crate holds a parser handle, and `acpi::aml_eval`
    is the only read side of it.

14. Power-management ownership: `crates/kernel/thermal` owns the thermal class
    (zones, trips, cooling devices, governors, the polling cadence and the
    attribute contract), `crates/kernel/cpufreq` owns frequency scaling (the
    operating-point table, the policy with its limit aggregation, the
    governors, the statistics) and `crates/kernel/cpuidle` owns idle-state
    selection (the state table, the governors, the per-CPU accounting). All
    three are leaves over `vfs`, `sync`, `kstrtox` and `cpu`; each carries a
    kernel-only child for the one thing it cannot decide alone — thermal's
    workqueue sweep, cpuidle's clock and generic halt driver, cpufreq's
    scheduler hook. `crates/kernel/sysfs` projects the thermal class and
    `crates/kernel/procfs` projects the two per-CPU trees under
    `/sys/devices/system/cpu`. `crates/kernel/sched` calls into cpuidle from
    its idle loop and feeds cpufreq the demand signal; neither may depend on
    `sched` in a host build. `crates/kernel/firmware` owns the ACPI providers.
    The terminal action for a critical thermal trip is installed by kernel
    init, because a device class does not own powering the machine down.
15. `crates/kernel/overlayfs` owns union-mount semantics: the layer stack, the
    merged lookup, whiteouts and opaque directories, copy-up, the merged
    directory stream, and the four records a layer carries
    (`trusted.overlay.{opaque,redirect,origin,metacopy,...}`, and their
    `user.` form). It is the only place any of those is written or read; no
    other crate may recognize a whiteout or a marker. It depends on `vfs` for
    the inode surface it drives the layers through, `syscall` for the errno
    type, `sync` and `klog`. `vfs` owns whiteout device number and rename-flag
    constants (`fs::mknod`, `namei::may_rename`) and knows nothing of layers;
    `syscalls::fsmount_common::registry` registers the type and resolves layer
    paths, holding no stacking state of its own.

## 6 Naming rules (frozen)

1. Prefer explicit names over compressed abbreviations.
   - Good: `syscall-handlers`, `namespace-cgroup`, `observability`
   - Avoid for new crates: short opaque names like `svc`, `obs`, `dl`
2. Use one naming style per layer:
   - crates: kebab-case package names
   - modules/files: snake_case
3. If a file name says `glue`, `shim`, or `adapter`, keep it short.
   Target: under 300 LOC; split or rename when it grows beyond adapter
   scope.
4. Prefixes `dev_`, `syscall_glue_` are legacy. New code uses domain
   module trees (`syscalls/fs.rs`, `drivers/net/mod.rs`, etc.).

## 7 Dependency direction (frozen)

Allowed high-level direction:

`arch -> shared -> domain/drivers -> kernel integration`

Constraints:
1. Domain crates do not depend on `kernel` crate.
2. Driver crates may depend on domain/shared/arch abstractions, not on
   unrelated high-level subsystems.
3. `tools/*` cannot be required by runtime kernel crates.
4. No userspace-runtime crate group exists (`crates/user/*` deleted 2026-08-01);
   userland comes from Fedora RPMs via `../images`.
5. `crates/kernel/network-namespace` is a leaf over shared synchronization;
   tasks, networking, nsfs, and syscall layers depend on it, never vice versa.
6. `crates/kernel/namespace-identity` is dependency-neutral; non-network and
   non-mount namespace consumers depend on it, never vice versa.
7. `crates/kernel/socket` may depend on VFS, scheduler, namespace, net, and
   netlink work APIs; it cannot depend on `syscall`, syscall handlers, user
   pointers, or implicit current-task lookup.
8. `crates/kernel/user-namespace` is a leaf over `namespace-identity`; `nscg`,
   procfs, and future credential-translation consumers depend on it, never
   vice versa.
9. `crates/kernel/ipc` may depend on `netlink` for `mq_notify(SIGEV_THREAD)`
   cookie delivery, mirroring Linux mqueue's `netlink_getsockbyfd` /
   `netlink_sendskb`; `netlink` never depends on `ipc`.
9a. `crates/kernel/audit` is a leaf over shared synchronization and the errno
   type: it reads no task, no socket, and no filesystem, so its whole decision
   surface runs hosted. `netlink`, `landlock`, `fs` and the syscall shims
   depend on it, never vice versa; the caller's namespaces, capabilities and
   process id are gathered by the transport and passed in.
10. `crates/kernel/security` may depend on `cgroup` to attach, query, and
    acquire effective cgroup BPF programs. `cgroup` stays independent of
    security policy and retains opaque VFS program objects.
11. `crates/kernel/power-supply` and `crates/kernel/backlight` are leaves over
    `vfs`/`sync`/`kstrtox`. `sysfs` and `firmware` depend on them, never the
    reverse; neither may depend on `firmware`, a driver crate, or a provider.
12. `crates/shared/kstrtox` is dependency-free: the Linux `kstrto*` conversion
    every sysfs `store` needs, in one place, not one parser per class.
13. `crates/kernel/overlayfs` is a leaf over `vfs`/`syscall`/`sync`/`klog`. It
    depends on no other filesystem and no block layer — its layers are
    directories reached through `vfs::Inode`, whatever holds them. The syscall
    shim depends on it, never the reverse.

## 8 Change policy

1. Structural moves are spec-visible. Update this doc + `MANIFEST` in
   the same PR when rules change.
2. Large code moves land in two steps when possible:
   - move with behavior-preserving wrappers
   - cleanup/rename after tests pass
3. Keep package names stable during path migration unless there is a
   clear collision or ambiguity problem.

## 9 Migration plan from current tree

1. Stage A: classify each `kernel/src/*.rs` file by owning crate.
   Artifact: `52a-stage-a-ownership-classification.md` (per-file map
   + B-sub-phase ordering).
2. Stage B: move real subsystem behavior out of `kernel/src` per the
   B-0..B-8 sub-phases pinned in `52a§11`.
3. Stage C: rename legacy `syscall_glue_*` and `dev_*` paths to domain
   module trees.
4. Stage D: add CI checks that block new boundary violations.

Temporary exceptions are allowed only with:
1. TODO marker with target crate/path.
2. Tracking issue/PR id.
3. Removal target phase.

## 10 CI guardrails (planned)

1. `xtask doc-check` validates this spec is present in `MANIFEST`.
2. Structural lint blocks:
   - new `kernel/src/syscall_glue_*` files above adapter scope
   - new subsystem implementations in `kernel/src` when owning crate
     already exists
3. Dependency lint verifies forbidden edges from §7.

## 11 Cross-references

- `02§1` lifecycle + drift policy.
- `07§8` workspace/toolchain orchestration.
- `08§7` file length cap.
- `39§3` existing workspace layout baseline.

## 12 Changelog

- 2026-08-16: Added `crates/kernel/overlayfs` as the single owner of
  union-mount semantics (layer stack, merged lookup, whiteouts, copy-up,
  merged readdir, layer records).
- 2026-08-16: Added the removable-media filesystem ownership boundary (`62`),
  `crates/kernel/sectors` as the single owner of the volume-sector adapter, and
  `crates/shared/dostime` as the single owner of the 1980-epoch date/time pair.
- 2026-08-15: Added the power-supply and backlight device-class ownership
  boundaries, their ACPI providers under `firmware`, and `crates/shared/kstrtox`.
- 2026-08-15: Added `crates/kernel/thermal`, `crates/kernel/cpufreq` and
  `crates/kernel/cpuidle`, the ACPI thermal provider under `firmware`, and the
  two scheduler entry points (idle-loop selection, demand signal).
- 2026-08-01: Removed the `crates/user/*` layer — this repo builds no userspace;
  userland is Fedora RPMs composed by `../images` (`29a§2`).
- 2026-07-29: Made `cgroup` the single owner of cgroup BPF attachment state;
  security verifies and executes immutable snapshots without a parallel
  registry.
- 2026-07-28: Added `crates/kernel/aslr` as the single owner of address-space randomization policy (budgets, mode, address math); removed `vmm::MMAP_BASE_GAP` and the fixed `PIE_LOAD_BIAS`/`INTERP_LOAD_BIAS` constants.
- 2026-07-26: Added `crates/kernel/user-namespace` id-map engine ownership boundary (real `uid_map`/`gid_map`/`setgroups`, replacing the procfs `SysctlInode` fake).
- 2026-07-15: Added dependency-neutral non-network/non-mount namespace identity ownership boundary.
- 2026-07-15: Added canonical cross-family socket work-layer ownership.
- 2026-07-14: Added dependency-neutral network-namespace ownership boundary.

## 13 OQ

1. Keep `kernel/` directory name, or move integration crate to
   `crates/kernel/integration/` after migration?
2. Rename existing short crates (`obs`,`nscg`) now, or only for new
   crates first and old crates later?
3. CI heuristic for adapter scope: LOC cap only, or AST-based rule
   (stateful type definitions + public mutating functions)?
