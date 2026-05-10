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
5. Userspace code and assets live under `userspace/` and `vendor/`,
   never in kernel subsystem crates.

## 4 Layout contract (target)

```text
oxide2/
├── kernel/                    # thin integration crate
├── crates/
│   ├── kernel/                # core subsystem crates
│   ├── drivers/               # driver crates
│   ├── arch/                  # arch + boot + kernel-bin crates
│   ├── shared/                # shared no_std libraries
│   └── user/                  # userspace runtime/auth/pkg libs
├── userspace/                 # C/Rust userspace binaries and tests
├── tools/                     # xtask, lint, build helpers
├── docs/                      # specs
├── tests/                     # integration/hosted test harnesses
└── vendor/                    # third-party sources/assets
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
4. Userspace libs under `crates/user/*` cannot be imported by kernel
   runtime crates.

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
2. Stage B: move real subsystem behavior out of `kernel/src`.
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

(none)

## 13 OQ

1. Keep `kernel/` directory name, or move integration crate to
   `crates/kernel/integration/` after migration?
2. Rename existing short crates (`dl`,`svc`,`pkg`,`obs`,`nscg`) now,
   or only for new crates first and old crates later?
3. CI heuristic for adapter scope: LOC cap only, or AST-based rule
   (stateful type definitions + public mutating functions)?
