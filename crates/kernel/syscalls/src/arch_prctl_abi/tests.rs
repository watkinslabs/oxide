// Hosted coverage for the `arch_prctl(2)` decision core. These run under
// `cargo test` on the HOST target — the slot file that consumes them is
// `#[cfg(target_os = "oxide-kernel")]` and therefore untestable.
//
// Test-module manifest:
//   tests/classify.rs — sub-code classification + the TASK_SIZE_MAX rule.
//   tests/cpuid.rs    — CPUID-faulting capability, mode round-trip, MSR values.
//   tests/shstk.rs    — the `ARCH_SHSTK_*` rule ladder.
//   tests/xcomp.rs    — xstate support/permission/request rules.
//   tests/lam.rs      — address-masking rules.
// The aarch64 "no arch_prctl at all" contract is pinned in the syscall
// crate's `arm_abi` tests, the only place that module is host-visible.

#[path = "tests/classify.rs"] mod classify_tests;
#[path = "tests/cpuid.rs"]    mod cpuid_tests;
#[path = "tests/shstk.rs"]    mod shstk_tests;
#[path = "tests/xcomp.rs"]    mod xcomp_tests;
#[path = "tests/lam.rs"]      mod lam_tests;
