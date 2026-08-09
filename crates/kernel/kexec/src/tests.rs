// Host-run provenance for the kexec contract. Manifest:
// - `fake`:     a page supply whose physical addresses the test chooses.
// - `gate`:     serialisation + reset for every case that reaches the store.
// - `order`:    the refusal ladders — permission, flags, segment list.
// - `staging`:  control pages, the relocation chain, the collision swap.
// - `file`:     the file-load ladder plus the one owner of the global slots.

mod fake;
mod gate;
mod order;
mod staging;
mod file;
