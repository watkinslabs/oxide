// Fork of an address space, one module per strategy.
//
// Module manifest:
//   `shared` — steps every strategy shares: the parent-side copy-on-write
//              decision, swap-leaf rollback, per-VMA inheritance, rmap publish.
//   `lazy`   — VMA tree only; the child demand-faults every page.
//   `cow`    — copy-on-write sharing of present pages plus inheritance of the
//              non-present leaves and the write-protect state riding on them.
//   `eager`  — copies every writable mapped page into fresh child frames.

mod shared;
mod lazy;
mod cow;
mod eager;

#[cfg(test)]
mod tests;
