# 07 Toolchain + Targets

FROZEN 2026-05-02. Dep:`02`,`08`.

One pinned nightly. Two custom target JSONs (kernel×2). Three build profiles. `panic=abort` everywhere kernel.

## 1 Toolchain

`rust-toolchain.toml`:
```toml
[toolchain]
channel = "nightly-2026-05-01"   # bumped per §1.1
components = ["rust-src","rustfmt","clippy","llvm-tools-preview","miri"]
targets = []                      # use -Zbuild-std
profile = "minimal"
```

Nightly required for: `-Zbuild-std`, custom target JSON, `naked_functions`, `asm_const`, `panic_immediate_abort`.

### 1.1 Bump cadence

Bump cadence is whatever the project's stability needs. PR title `toolchain: bump to nightly-YYYY-MM-DD` with: rationale, full CI green incl miri, source delta for renamed unstable features.

### 1.2 Stable migration

When all `-Z` flags stable + targets upstreamed (Redox precedent) + `-Zbuild-std` replaced. Until then, nightly.

## 2 Build profiles

```toml
[profile.release]
opt-level=3 lto="fat" codegen-units=1
panic="abort" debug="limited" overflow-checks=false incremental=false

[profile.dev]
opt-level=1 lto="off" codegen-units=16
panic="abort" debug="full" overflow-checks=true incremental=true

[profile.debug-build]
inherits="dev"  # + --features debug-all (`04§3`)
```

Rules: all kernel profiles `panic="abort"`. `release` IS the perf profile (no separate one). `opt-level=0` not used (10–50× slower; kernel unrunnable).

No userspace profile here: userspace binaries are Fedora RPM builds (`29a§2`), not built by this repo.

## 3 Targets (`targets/`)

### 3.1 `x86_64-unknown-oxide-kernel`

```json
{
  "arch":"x86_64", "code-model":"kernel", "cpu":"x86-64-v3",
  "data-layout":"e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128",
  "disable-redzone":true,
  "features":"-mmx,-sse,-sse2,-sse3,-ssse3,-sse4.1,-sse4.2,-avx,-avx2,+soft-float",
  "rustc-abi":"x86-softfloat",
  "linker":"rust-lld", "linker-flavor":"ld.lld",
  "llvm-target":"x86_64-unknown-none",
  "max-atomic-width":64, "panic-strategy":"abort",
  "position-independent-executables":false, "relocation-model":"static",
  "relro-level":"off", "stack-probes":{"kind":"inline"},
  "static-position-independent-executables":false,
  "supported-sanitizers":[], "supports-stack-protector":true,
  "target-endian":"little", "target-pointer-width":64,
  "vendor":"unknown", "os":"oxide-kernel"
}
```

ISA floor `x86-64-v3` (Haswell+) per `03§7`. SSE/AVX off (kernel doesn't save them). Lazy FPU save in `14§7`. `code-model=kernel` for upper-half RIP-relative. `disable-redzone` so IRQ handlers don't clobber SysV scratch zone. Static reloc; KASLR via boot relocation (`27§9`).

### 3.2 `aarch64-unknown-oxide-kernel`

```json
{
  "arch":"aarch64", "cpu":"generic",
  "data-layout":"e-m:e-p270:32:32-p271:32:32-p272:64:64-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128-Fn32",
  "disable-redzone":true,
  "abi":"softfloat", "rustc-abi":"softfloat",
  "features":"+strict-align,-fp-armv8,-neon",
  "linker":"rust-lld", "linker-flavor":"ld.lld",
  "llvm-target":"aarch64-unknown-none",
  "max-atomic-width":128, "panic-strategy":"abort",
  "relocation-model":"static",
  "supported-sanitizers":[], "supports-stack-protector":true,
  "target-endian":"little", "target-pointer-width":64,
  "os":"oxide-kernel"
}
```

No FP/NEON kernel; lazy FPSIMD trap. `+strict-align` (`SCTLR_EL1.A=1`); catches alignment bugs early. `cpu=generic` (ARMv8.2-A); GICv3 floor (Cortex-A75/M1+).

### 3.3 Userspace targets (none owned here)

This repo owns no userspace target. Userspace is Fedora `-gnu` binaries installed from RPMs (`29a§2`); their triples are `x86_64-unknown-linux-gnu` / `aarch64-unknown-linux-gnu` as Fedora builds them. Nothing in this repo cross-compiles against them.

Custom `*-unknown-oxide` userspace targets considered + rejected: would require porting `std` (Redox-style work) for no user-visible benefit while the Linux-compat surface is the target.

Dynamic linker is Fedora's `ld-linux-x86-64.so.2` / `ld-linux-aarch64.so.1`, shipped by the `glibc` RPM (`29a§4`).

### 3.4 Build chain (kernel only)

Kernel binary depends on `rustc` + the kernel target JSON only. No libc, no userspace headers, no UAPI export step. Built directly:

```
cargo -Z build-std --target ./targets/<arch>-unknown-oxide-kernel.json -p kernel
```

| Step | Artifact | Source | Consumes |
|---|---|---|---|
| 1 | cross-toolchain | `rust-toolchain.toml` (rustc) | — |
| 2 | kernel ELF | `xtask kernel --arch <a>` | step 1 |
| 3 | boot image | `xtask artifacts` + `xtask grub`/`image` | step 2 + rootfs |

Rootfs is an input, not a product: `../images` composes and packs `<profile>-<arch>-root.img` from RPMs, and this repo copies it (`29§5`). The kernel↔userspace contract is the Linux syscall ABI in `15` — no source crosses the boundary.

## 4 Build cmds

```
xtask kernel --arch x86_64 --profile release
# expands to:
cargo build -Z build-std=core,compiler_builtins,alloc \
  -Z build-std-features=compiler-builtins-mem \
  --target ./targets/x86_64-unknown-oxide-kernel.json \
  --profile release -p kernel
```

`xtask` wraps target JSON, `-Zbuild-std`, image composition, QEMU.

## 5 Build-time discipline rules

Scope: these bind the KERNEL BUILD. Host-test code (`#[cfg(test)]`), hosted builds (`feature = "hosted"`, `#[cfg(not(target_os = "oxide-kernel"))]`) and dev-tool crates under the `02` carve-out are out of scope, and a count that does not filter them is not a violation count. Every lint below filters this way; audits must use the linter's number (`make audit-counts`), never a raw grep.

- `panic="abort"` every kernel profile. Build-test: `panic!("foo")` → no unwind tables in `.text`.
- No `static mut` outside `#[cfg(test)]`. CI grep, build fail. Per `06§11`.
- No `dyn HAL trait`. Post-build `nm | grep -E 'vtable.*<.* as oxide::hal::(MmuOps|CpuOps|Context|IrqOps|TimerOps)>'` → fail. Per `05§C1`.
- `kassert!(cond, "literal")` only; no `panic!(fmt)`. Kernel build only — host test code is out of scope, since `assert_eq!` expands to exactly this construct. Enforced by `code/panic-fmt`, which skips off-kernel lines; a raw `panic!(.*\{` grep counts ~113 legitimate host-test sites and is not the rule.
- **No magic numbers for typed ABI constants.** Errno values, `OpenFlags`, `MAP_*`, `SOCK_*`, `SO_*`, signal numbers, syscall slot numbers go through their typed enum (`syscall::errno::Errno`, `vfs::OpenFlags`, `sched::sig::Signum`, `syscall::nrs::*`, etc.). A bare integer assigned to a field named `*_eno` / `*_errno` / `*_signo` / `*_slot`, or compared against an integer in an errno/signal/flag context, is a CI lint failure (`code/magic-errno`). Adds-to-enum first, uses-the-name second. Local constants for non-ABI numeric thresholds (RTO ms, retry counts, buffer sizes) are fine — name them `const FOO_NS: u64 = …;` so reviewers see the meaning.
- `# C:` on every `pub fn`. CI lint via `tools/spec-lint/`. Per `04§1.2`.
- `// SAFETY: <≥30 chars naming invariant>` on every `unsafe { }`. CI lint.
- klog macros only accept `&'static str` format strings (compile-time interned). No `format!()` results passed in. CI grep.
- `#![no_std]` every kernel crate. `extern crate std` in any kernel binary → fail. Reaching the kernel build is what makes it a violation: a site behind `#[cfg(not(target_os = "oxide-kernel"))]`, `#[cfg(any(test, feature = "hosted"))]`, or an enclosing `#[cfg(test)] mod` is compliant, as is a dev-tool crate under the `02` carve-out (`tools/spec-lint`, `crates/kernel/conformance`). A raw grep counts ~73 sites, none of them violations.

```rust
#[macro_export] macro_rules! kassert {
  ($c:expr, $m:literal) => { if !$c { $crate::panic_static($m, file!(), line!()) } };
}
```

## 6 Linker

`rust-lld` both arches. No GNU ld.

Scripts (FROZEN once boot works; revision required to change):
- `link/x86_64-kernel.ld` — kernel @ `0xFFFF_FFFF_8000_0000`. Sections: `.text.boot,.text,.rodata,.data,.bss,.percpu,.klog_strings,.init_array`.
- `link/aarch64-kernel.ld` — kernel @ `0xFFFF_0000_0000_0000`. Same shape.

Custom sections:
- `.percpu`: linker emits 1 copy; runtime allocates `MAX_CPUS` copies; per-CPU `GS_BASE`/`TPIDR_EL1` points to slot. Vars use `#[link_section=".percpu"]`.
- `.klog_strings`: interned format strings; userspace decoder resolves by addr.

## 7 Build artifacts

```
target/builds/<id-or-default>/
  <arch>-unknown-oxide-kernel/<profile>/oxide-<arch>  # ELF snapshot
  root-<arch>.img                                      # ext4 root disk
  oxide-<arch>-grub.iso                                # boot ISO
```

## 8 xtask

`tools/xtask/` workspace-member host binary; sole CI entry point.

```
xtask kernel    --arch <x86_64|aarch64> --profile <release|dev|debug-build>
xtask artifacts --arch <a>
xtask rootfs    --arch <a>            # copies the ../images pre-packed root image
xtask image     --arch <a>
xtask grub      --arch <a>
xtask test      [--hosted|--kernel|--loom|--miri|--proptest]
xtask conformance
xtask spec-lint
xtask doc-check
```

## 9 Test contract (frozen)

- Two kernel target JSONs in `targets/`; hello-world `no_std` kernel builds for each.
- `xtask kernel --arch x86_64` and `--arch aarch64` clean-checkout success.
- §5 lints in `tools/spec-lint/`; clean kernel passes.
- `static mut FOO` injected → build fail with clear msg.
- `panic!("err: {}", x)` injected → build fail. Injected into host-test code → NO finding (scope, §5).
- An audit count for a scoped rule equals the linter's count, not a raw grep: `make audit-counts` reports 0 `panic!(fmt)` and 0 `extern crate std` against a clean kernel build.
- `Box<dyn MmuOps>` injected → post-build vtable grep fail.
- `make qemu-x86` / `make qemu-arm` boot the kernel through the GRUB runner.
- Toolchain bump PR template documented (`CONTRIBUTING.md`).

## 10 Cross-spec

`04`,`06`,`36`,`38`,`39`.

## 11 Changelog

(none)
