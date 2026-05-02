# 42 Test Strategy

DRAFT 2026-05-02. Dep:`02`,`05`,`06`,`07`,`08`,`40`.
## 1 Purpose

Concrete patterns: oracle property tests, loom, miri, hosted vs in-kernel tests, fuzz, soak. How each integrates with the workspace and CI.

## 2 Invariants (frozen)

1. Every algorithmic crate has hosted unit tests + property tests vs an oracle.
2. Every lockless data structure has a loom test.
3. Every hostable crate runs under miri in CI.
4. Every subsystem with a "Test contract" section in its spec has those tests implemented and green before the spec freezes.
5. Coverage gates per `42§10`.

## 3 Test taxonomy

| Kind | Where | Runner | Speed |
|---|---|---|---|
| Hosted unit | `crates/<x>/src/**` `#[cfg(test)]` | `cargo test --target host` | fast |
| Property (proptest) | `crates/<x>/tests/prop/` | `cargo test prop` | medium |
| Loom | `crates/<x>/tests/loom/` | `RUSTFLAGS=--cfg loom cargo test` | slow |
| Miri | hosted unit tests under miri | `cargo +nightly miri test` | slow |
| In-kernel | `tests/integration/` | `xtask test --kernel` boots image w/ test runner | medium |
| QEMU smoke | `tests/qemu/` | `xtask qemu` w/ expected output match | fast |
| Bench | `bench/` (criterion or custom) | `xtask bench` | medium |
| Soak | `tests/soak/<workload>` | `tools/soak-runner` | hours |
| Fuzz | `fuzz/<crate>/` | `cargo fuzz run` | continuous |

## 4 Oracle pattern

For algorithm A:
- Write `crates/<a>/src/lib.rs` (production impl, fast).
- Write `tools/oracle-<a>/src/lib.rs` (deliberately stupid, slow, obviously correct).
- Write `crates/<a>/tests/prop/<a>_oracle.rs`:

```rust
proptest! {
    #[test]
    fn matches_oracle(ops in op_seq()) {
        let mut prod = ProdImpl::new();
        let mut orcl = OracleImpl::new();
        for op in ops {
            let r1 = prod.apply(&op);
            let r2 = orcl.apply(&op);
            assert_eq!(r1, r2);
            assert_eq!(prod.observable_state(), orcl.observable_state());
        }
    }
}
```

Oracle defines `observable_state()` so prod and oracle compare like-with-like.

## 5 Loom pattern

For lockless DS L:
- Build the DS with `loom::sync::atomic::*` instead of `core::sync::atomic::*` (cfg-gated).
- Write `tests/loom/<l>.rs`:

```rust
#[test]
fn no_uaf() {
    loom::model(|| {
        let l = Arc::new(L::new());
        let h1 = thread::spawn({...});
        let h2 = thread::spawn({...});
        h1.join(); h2.join();
        // assertions
    });
}
```

Bound depth via `LOOM_MAX_BRANCHES`/`LOOM_MAX_DURATION` env. Default depth: 6 (concurrency tests budget).

## 6 Miri pattern

`cargo +nightly miri test --target x86_64-unknown-linux-gnu` on hostable crates. Miri config:
- `-Zmiri-strict-provenance`
- `-Zmiri-tag-raw-pointers`
- `-Zmiri-tree-borrows` (eventually)

Hostable = no MMIO, no `core::arch::asm!`, no inline asm. Most algorithm crates qualify; HAL crates don't.

## 7 In-kernel test runner

`tests/integration/<test>/` is a tiny userspace binary that boots in our initramfs, runs the scenario, prints `TEST PASS\n` or `TEST FAIL: <reason>\n` and `exit_group(0|1)`.

`xtask test --kernel <name>` builds it into the initramfs, boots QEMU, parses serial.

Used for: VFS scenarios, syscall scenarios, signal delivery, mmap/fork combinations.

## 8 Fuzz

`cargo-fuzz` integration:
- `fuzz/parsers/elf-parse/` — random bytes → ELF parser; assert no panic.
- `fuzz/parsers/cpio-parse/` — initramfs decoder.
- `fuzz/syscall-table/` — random regs into dispatch (in-kernel fuzz harness).
- `fuzz/net/{tcp,udp,ip}/` — random packet stream into stack.

Continuous on a corpus dir; failed inputs auto-saved as regression tests.

## 9 Soak workloads

`tests/soak/<name>/`:

| Workload | Stresses |
|---|---|
| pmm-mix | `10` (random alloc/free with poison injection) |
| slab-mix | `12` |
| sched-canary | `13`+`14` (canary + 1ms preempt) |
| fs-stress | `16`+`17` (fs_mark + find + concurrent touch/unlink) |
| net-loopback | `25` (iperf3 + curl loops) |
| build-self | full kernel build of itself in a loop |
| stress-ng | external `stress-ng --cpu --vm --hdd` if integrated |

Background rotation (per `40§3`): each subsystem's primary workload + `stress-ng` mixed; 4h cycles on `main`. Failures → tickets; not phase-gating.

## 10 Coverage

LLVM coverage (`-C instrument-coverage`) on hosted tests. `tools/coverage/` aggregates and writes `coverage/<crate>.html`.

Gates per `42§10`. Subsystem-specific in each spec's `Test contract`.

## 11 Static analysis

- `clippy::pedantic` (with documented exceptions in `clippy.toml`).
- `cargo deny` for licenses + advisories.
- `tools/spec-lint/`: enforces `// SAFETY:`, `# Complexity:`, `# Lk:`, `# Ctx:`, `# Sleeps:` markers per `09`.
- `cargo asm` snapshot tests: confirm `kdebug!(off)` and `klog::trace!(off)` produce no asm.

## 12 Test contract for tests themselves

- Loom test that hangs >30s in CI → fail with diagnostic.
- Miri run >20m → fail.
- A test that passes 100 times then fails once → quarantine; investigate.

## 13 Cross-spec

`02`,`05`,`40`. Every subsystem spec's `Test contract` section.

## 14 Open Questions

- Property test seed reproducibility: store last failing seed per crate in `proptest-regressions/`. Lean: yes (proptest does this).
- Mutation testing (cargo-mutants): nice but expensive. Defer to v1.x.
- Symbolic execution (kani / creusot): aspirational; defer.
