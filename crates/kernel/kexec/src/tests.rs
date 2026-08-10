// Host-run provenance for the kexec contract. Manifest:
// - `fake`:     a page supply whose physical addresses the test chooses.
// - `gate`:     serialisation + reset for every case that reaches the store.
// - `order`:    the refusal ladders — permission, flags, segment list.
// - `staging`:  control pages, the relocation chain, the collision swap.
// - `file`:     the file-load ladder plus the one owner of the global slots.
// - `crashk`:   the `crashkernel=` grammar, the placement, and the shrink.
// - `machine`:  the identity tables the trampoline runs under and the walk it
//               performs over a staged chain.

mod fake;
mod gate;
mod order;
mod staging;
mod file;
mod machine;
mod crashk;
