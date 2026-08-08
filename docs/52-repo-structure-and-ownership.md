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
