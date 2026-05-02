# 07 Toolchain + Targets

DRAFT 2026-05-02. Dep:`02`,`08`.

One pinned nightly. Four custom target JSONs (kernel×2, user×2). Three build profiles. `panic=abort` everywhere kernel.

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

Min once/6mo, max once/6wk. PR title `toolchain: bump to nightly-YYYY-MM-DD` with: rationale, full CI green incl miri, source delta for renamed unstable features.

### 1.2 Stable migration

When all `-Z` flags stable + targets upstreamed (Redox precedent) + `-Zbuild-std` replaced. v2+. v1 nightly.

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

Userspace targets `*-unknown-linux-musl` (per `29a§2`): standard Cargo profiles; `panic="unwind"` default with musl unwinder. Same toolchain pin.

## 3 Targets (`targets/`)

### 3.1 `x86_64-unknown-oxide-kernel`

```json
{
  "arch":"x86_64", "code-model":"kernel", "cpu":"x86-64-v3",
  "data-layout":"e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128",
  "disable-redzone":true,
  "features":"-mmx,-sse,-sse2,-sse3,-ssse3,-sse4.1,-sse4.2,-3dnow,-3dnowa,-avx,-avx2,+soft-float",
  "linker":"rust-lld", "linker-flavor":"ld.lld",
  "llvm-target":"x86_64-unknown-none",
  "max-atomic-width":64, "panic-strategy":"abort",
  "position-independent-executables":false, "relocation-model":"static",
  "relro-level":"off", "stack-probes":{"kind":"inline"},
  "static-position-independent-executables":false,
  "supported-sanitizers":[], "supports-stack-protector":true,
  "target-c-int-width":"32", "target-endian":"little", "target-pointer-width":"64",
  "vendor":"unknown", "os":"oxide-kernel", "is-builtin":false
}
```

ISA floor `x86-64-v3` (Haswell+) per `03§7`. SSE/AVX off (kernel doesn't save them). Lazy FPU save in `14§7`. `code-model=kernel` for upper-half RIP-relative. `disable-redzone` so IRQ handlers don't clobber SysV scratch zone. Static reloc; KASLR via boot relocation (`27§9`).

### 3.2 `aarch64-unknown-oxide-kernel`

```json
{
  "arch":"aarch64", "cpu":"generic",
  "data-layout":"e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128",
  "disable-redzone":true,
  "features":"+strict-align,-fp-armv8,-neon",
  "linker":"rust-lld", "linker-flavor":"ld.lld",
  "llvm-target":"aarch64-unknown-none",
  "max-atomic-width":128, "panic-strategy":"abort",
  "relocation-model":"static",
  "supported-sanitizers":[], "supports-stack-protector":true,
  "target-endian":"little", "target-pointer-width":"64",
  "os":"oxide-kernel", "is-builtin":false
}
```

No FP/NEON kernel; lazy FPSIMD trap. `+strict-align` (`SCTLR_EL1.A=1`); catches alignment bugs early. `cpu=generic` (ARMv8.2-A); GICv3 floor (Cortex-A75/M1+).

### 3.3 Userspace targets (RESOLVED per `29a§2` — Linux-look-alike, not `os=oxide`)

Userspace targets are upstream Rust targets. No custom JSON. Per `29a§2`:

| Target | Use |
|---|---|
| `x86_64-unknown-linux-musl` | userspace x86 |
| `aarch64-unknown-linux-musl` | userspace arm |

These are stock Rust targets. `std` works. Tokio/hyper/serde/etc. build unchanged. Cross-compile via `cargo build --target x86_64-unknown-linux-musl`.

Custom `*-unknown-oxide` userspace targets considered + rejected for v1: would require porting `std` (~1yr Redox-style work) for no v1-visible benefit. Migration path to `os=oxide` deferred to v2 when distinct userspace ABI surface emerges.

Userspace dynamic linker still `/lib/ld-oxide.so.1` (our musl-fork ld.so) per `29a§4`. Cross-compile from any Linux/Mac dev box.

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

- `panic="abort"` every kernel profile. Build-test: `panic!("foo")` → no unwind tables in `.text`.
- No `static mut` outside `#[cfg(test)]`. CI grep, build fail. Per `06§11`.
- No `dyn HAL trait`. Post-build `nm | grep -E 'vtable.*<.* as oxide::hal::(MmuOps|CpuOps|Context|IrqOps|TimerOps)>'` → fail. Per `05§C1`.
- `kassert!(cond, "literal")` only; no `panic!(fmt)`. CI grep `panic!(.*\{` → fail.
- `# C:` on every `pub fn`. CI lint via `tools/spec-lint/`. Per `04§1.2`.
- `// SAFETY: <≥30 chars naming invariant>` on every `unsafe { }`. CI lint.
- klog macros only accept `&'static str` format strings (compile-time interned). No `format!()` results passed in. CI grep.
- `#![no_std]` every kernel crate. `extern crate std` in any kernel binary → fail.

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
target/<triple>/<profile>/
  kernel             # ELF
  kernel.bin         # objcopied raw
  initramfs.cpio.zst
  boot.img           # ESP w/ kernel+initramfs+bootloader cfg
  debug-symbols/     # split debuginfo (gdb, decoder)
```

## 8 xtask

`tools/xtask/` workspace-member host binary; sole CI entry point.

```
xtask kernel    --arch <x86_64|aarch64> --profile <release|dev|debug-build>
xtask user      --arch <a>
xtask image     --arch <a>
xtask test      [--hosted|--kernel|--loom|--miri|--proptest]
xtask qemu      --arch <a> [--gdb] [--smp N] [--mem MB]
xtask soak      --arch <a> --duration H
xtask bench     --arch <a>
xtask spec-lint
xtask doc-check
```

## 9 Test contract (frozen)

- Four target JSONs in `targets/`; hello-world `no_std` kernel builds for each.
- `xtask kernel --arch x86_64` and `--arch aarch64` clean-checkout success.
- §5 lints in `tools/spec-lint/`; clean kernel passes.
- `static mut FOO` injected → build fail with clear msg.
- `panic!("err: {}", x)` injected → build fail.
- `Box<dyn MmuOps>` injected → post-build vtable grep fail.
- `xtask qemu --arch x86_64`/`--arch aarch64` boot hello-world + clean exit.
- Toolchain bump PR template documented (`CONTRIBUTING.md`).

## 10 Cross-spec

`04`,`06`,`36`,`38`,`39`.

## 11 Changelog

(none)

## 12 OQ

- AVX/SSE in select kernel hot paths (`memcpy`/checksum)? Lean: no; cost of save-on-every-entry huge per `14§7`.
- Stack canaries (`+stack-protector=strong`): kernel default on; `+nostack-protect` cfg for hot paths if bench shows. Provide `__stack_chk_fail`/`__stack_chk_guard`.
- `code-model` aarch64: not in JSON; PC-relative ±2GiB suffices; document in linker script.
- Hosted tests for kernel crates: `[target.'cfg(test)']` to host triple; pattern in `42`.
- Upstream `*-unknown-oxide-kernel` to rustc: after v1 + 2y ABI stability. Userspace `*-unknown-oxide`: only when v2 wants distinct ABI per `29a§2`.
