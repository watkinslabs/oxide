// Address-space layout randomisation — the single owner of every per-exec
// address randomisation this kernel performs, per `27` and `31§6`.
//
// Module manifest:
//   `limits` — entropy budgets (`ARCH_MMAP_RND_BITS*`, `STACK_RND_MASK`) and
//              the address anchors (`ELF_ET_DYN_BASE`, `STACK_TOP`, gaps).
//   `mode`   — the live `kernel.randomize_va_space` cell and the per-exec
//              `PF_RANDOMIZE` decision.
//   `layout` — pure address math mirroring `mm/util.c` + `fs/binfmt_elf.c`.
//              Every function takes its random word as an argument, so the
//              placement rules are testable without an RNG.
//   `exec`   — `ExecRnd`: the per-exec draw. One CRNG read per randomised
//              quantity, taken once at execve and threaded through the loader.
//   `tunable`— the `vm.mmap_rnd_bits` sysctl cell (bounded by `limits`).
//
// Entropy comes from `crng` (the kernel CSPRNG) and nowhere else. A second
// generator here is how predictable offsets reach ASLR by accident — the same
// failure the clock-derived `AT_RANDOM` had before `F768`.

#![no_std]

#[cfg(test)]
extern crate std;

pub mod exec;
pub mod layout;
pub mod limits;
pub mod mode;
pub mod tunable;

#[cfg(test)]
mod tests;

pub use exec::ExecRnd;
pub use limits::{Budget, AARCH64, CURRENT, ELF_ET_DYN_BASE, STACK_TOP, X86_64};
pub use mode::{Mode, randomize_va_space, set_randomize_va_space};
